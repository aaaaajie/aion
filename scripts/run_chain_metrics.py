"""Event-based result delivery, observer, adoption and final cleanup metrics."""

from collections import Counter
from datetime import datetime


class ChainMetrics:
    def __init__(self):
        self.sequence = 0
        self.observer = Counter()
        self.observer_errors = Counter()
        self.observer_stages = Counter()
        self.delivery_pending = {}
        self.delivery_confirmed = set()
        self.delivery_presented = set()
        self.delivery_expired = set()
        self.delivery_pages = Counter()
        self.delivery_latency_ms = []
        self.delivery_confirmation_ms = []
        self.checks = {}
        self.check_results = {}
        self.check_adopted = set()
        self.active_check = {}
        self.references = Counter()
        self.cleanup = {}
        self.worker_terminals = {}
        self.worker_cleanup = {}
        self.worker_keys = {}

    def record(self, kind, payload, agent_id, sequence, created_at):
        self.sequence = max(self.sequence, sequence)
        if kind == "solver_observation_started":
            self.observer["started"] += 1
        elif kind == "solver_observation_snapshot":
            outcome = "success" if payload.get("advice") is not None and not payload.get("error") else "failed" if payload.get("error") else "unavailable"
            self.observer[outcome] += 1
            error = payload.get("error")
            if error:
                self.observer_errors[error.get("code", "unclassified") if isinstance(error, dict) else "unclassified"] += 1
                self.observer_stages[error.get("stage", "unavailable") if isinstance(error, dict) else "unavailable"] += 1
        elif kind in {"solver_observation_cancelled", "solver_observation_discarded"}:
            self.observer["cancelled" if kind.endswith("cancelled") else "stale"] += 1
        elif kind == "tool_result_delivery_pending":
            self.delivery_pending[payload["delivery_key"]] = (created_at, agent_id, payload["scope"])
        elif kind == "tool_result_delivery_presented":
            key = payload["delivery_key"]
            if key not in self.delivery_presented and key in self.delivery_pending:
                start = datetime.fromisoformat(self.delivery_pending[key][0])
                self.delivery_latency_ms.append(max(0, int((datetime.fromisoformat(created_at) - start).total_seconds() * 1000)))
            self.delivery_presented.add(key)
        elif kind == "tool_result_delivery_confirmed":
            key = payload["delivery_key"]
            if key not in self.delivery_confirmed:
                self.delivery_confirmed.add(key)
                for page in payload["pages"]:
                    self.delivery_pages["complete" if page["presentation_complete"] else "deferred"] += 1
                if key in self.delivery_pending:
                    start = datetime.fromisoformat(self.delivery_pending[key][0])
                    self.delivery_confirmation_ms.append(max(0, int((datetime.fromisoformat(created_at) - start).total_seconds() * 1000)))
        elif kind == "tool_result_delivery_dropped":
            self.delivery_pages["dropped_before_delivery"] += 1
        elif kind == "solver_progress_check_started":
            self.checks[payload["check_key"]] = payload
            self.active_check[agent_id] = payload["check_key"]
        elif kind == "solver_progress_check_finished":
            self.check_results.setdefault(payload["check_key"], payload)
            self.active_check.pop(agent_id, None)
        elif kind == "challenge_progress_recorded" and "solver_review_new_information" in payload.get("progress_kinds", []):
            if agent_id in self.active_check:
                self.check_adopted.add(self.active_check[agent_id])
        elif kind == "tool_result":
            code = payload.get("error_code") or ((payload.get("result") or {}).get("error") or {}).get("code")
            if code in {"invalid_reference", "reference_type_mismatch", "evidence_not_found", "report_not_found",
                        "context_not_accessible", "evidence_not_accessible", "capability_verifier_foreign_handle",
                        "http_interaction_not_found"}:
                self.references[code] += 1
        elif kind == "worker_terminal_finalized":
            self.worker_terminals.setdefault(agent_id, payload)
        elif kind in {"worker_resource_cleanup", "worker_cleanup_reconciled"}:
            self.worker_cleanup[agent_id] = payload
        elif kind == "container_cleanup_result":
            self.cleanup[(payload["unique_code"], payload.get("generation"))] = payload
        if kind in {"worker_terminal_finalized", "agent_resources_invalidated", "solver_strategy_reset"}:
            self.delivery_expired.update(k for k, (_, owner, scope) in self.delivery_pending.items()
                if owner == agent_id and (kind == "worker_terminal_finalized" or
                    kind == "agent_resources_invalidated" and scope["generation"] != payload.get("generation") or
                    kind == "solver_strategy_reset" and scope["strategy_revision"] != payload.get("strategy_revision")))

    def result(self):
        observed = sum(self.observer.get(k, 0) for k in ("success", "failed"))
        check_outcomes = Counter(p.get("status", "unavailable") for p in self.check_results.values())
        check_reasons = Counter(p.get("reason", "unavailable") for p in self.check_results.values())
        stagnation = [p for a, p in self.worker_terminals.items() if self.worker_keys.get(a, "").startswith("stagnation:")]
        return {
            "observer": {"outcomes": dict(self.observer), "error_codes": dict(self.observer_errors), "failure_stages": dict(self.observer_stages),
                "valid_advice_rate": self.observer["success"] / observed if observed else None},
            "result_delivery": {"available": bool(self.delivery_pending), "pending_exchanges": len(self.delivery_pending.keys() - self.delivery_confirmed - self.delivery_expired),
                "scope_ended_without_delivery": len(self.delivery_expired - self.delivery_confirmed),
                "confirmed_exchanges": len(self.delivery_confirmed), "pages": dict(self.delivery_pages),
                "dropped_before_delivery": self.delivery_pages["dropped_before_delivery"] if self.delivery_pending else None,
                "first_delivery_latency_ms": self.delivery_latency_ms,
                "confirmation_latency_ms": self.delivery_confirmation_ms},
            "progress_adoption": {"available": bool(self.checks), "started": len(self.checks), "finished": len(self.check_results),
                "outcomes": dict(check_outcomes), "reasons": dict(check_reasons), "validated_adoptions": len(self.check_adopted),
                "model_requests": sum(p.get("requests", 0) for p in self.check_results.values()),
                "duration_ms": sum(p.get("duration_ms", 0) for p in self.check_results.values())},
            "reference_errors": dict(self.references),
            "cleanup": {"available": bool(self.cleanup), "targets": list(self.cleanup.values()),
                "confirmed": sum(p["released"] for p in self.cleanup.values()),
                "release_pending": sum(not p["released"] for p in self.cleanup.values())},
            "stagnation_final_results": dict(Counter(p["status"] for p in stagnation)),
        }
