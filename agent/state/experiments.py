"""Shared factual blackboard backed by immutable Evidence, without schema changes."""

import json
from sqlalchemy import select

from agent.experiment_records import RECORD_TYPE, experiment_index, portable
from .models import AgentRecord, EvidenceRecord
from .schemas import CapabilityContext


class ExperimentState:
    async def capture_experiment_scope(self, run_id, agent_id):
        """Capture execution conditions before work starts, not when it finishes."""
        async with self.db.sessions() as session:
            agent = await session.get(AgentRecord, agent_id)
            if agent is None or agent.run_id != run_id:
                raise ValueError("Experiment owner does not belong to run")
            owner = agent
            if agent.role == "worker":
                owner = await session.scalar(select(AgentRecord).where(
                    AgentRecord.run_id == run_id, AgentRecord.unique_code == agent.unique_code,
                    AgentRecord.role == "solver")) or agent
            challenge = await self._require_challenge(session, run_id, agent.unique_code) if agent.unique_code else None
            return {"resource_generation": owner.resource_generation,
                    "strategy_revision": challenge.strategy_revision if challenge else None}

    async def record_experiment(self, run_id, agent_id, record, *, source_sequence=None):
        async with self.db.sessions() as session:
            agent = await session.get(AgentRecord, agent_id)
            if agent is None or agent.run_id != run_id:
                raise ValueError("Experiment owner does not belong to run")
            challenge = await self._require_challenge(session, run_id, agent.unique_code)
            owner_generation = agent.resource_generation
            if agent.role == "worker":
                solver = await session.scalar(select(AgentRecord).where(
                    AgentRecord.run_id == run_id, AgentRecord.unique_code == agent.unique_code, AgentRecord.role == "solver"))
                owner_generation = solver.resource_generation if solver else owner_generation
            record = portable({**record, "record_type": RECORD_TYPE,
                "record_version": 1, "tool_version": record.get("tool_version", "unknown"),
                "unique_code": agent.unique_code, "resource_generation": record.get("resource_generation", owner_generation),
                "strategy_revision": record.get("strategy_revision", challenge.strategy_revision),
                "recorded_at": self.clock().isoformat(), "source_sequence": source_sequence})
            context = CapabilityContext(run_id=run_id, agent_id=agent_id, role=agent.role, unique_code=agent.unique_code)
        if source_sequence is None:
            record["source_sequence"] = await self.append_agent_event(run_id, agent_id, "experiment_execution_receipt",
                {"tool": record["tool"], "input_digest": record.get("input_digest"),
                 "unique_code": record["unique_code"], "resource_generation": record["resource_generation"]})
        saved = await self.persist_evidence(run_id, context, evidence_type=RECORD_TYPE,
            source=record["tool"], content=json.dumps(record, ensure_ascii=False),
            metadata=experiment_index(record))
        await self.append_agent_event(run_id, agent_id, "experiment_recorded", {
            **experiment_index(record), "unique_code": record["unique_code"],
            "evidence_ref": saved["evidence_ref"],
        })
        return saved

    async def experiment_context(self, run_id, unique_code, *, offset=0, limit=30):
        async with self.db.sessions() as session:
            generation = await session.scalar(select(AgentRecord.resource_generation).where(
                AgentRecord.run_id == run_id, AgentRecord.unique_code == unique_code, AgentRecord.role == "solver"))
            rows = (await session.scalars(select(EvidenceRecord).where(
                EvidenceRecord.run_id == run_id, EvidenceRecord.unique_code == unique_code,
                EvidenceRecord.evidence_type == RECORD_TYPE,
            ).order_by(EvidenceRecord.metadata_json["source_sequence"].as_integer().desc(), EvidenceRecord.evidence_id))).all()
        indices = []
        batches = {}
        seen = {}
        for row in reversed(rows):
            meta = dict(row.metadata_json or {})
            key = (meta.get("tool"), meta.get("target"), meta.get("input_digest"), meta.get("resource_generation"))
            ref = f"evidence:{row.evidence_id}"
            item = {**meta, "evidence_ref": ref}
            out = meta.get("output", {})
            complete = (out.get("body_complete") is True or out.get("status") == "completed") and not any(
                out.get(k) for k in ("truncated", "output_incomplete", "timed_out", "outcome_unknown"))
            if key in seen and key[2] and complete:
                item["same_input_previous_ref"] = seen[key]
            if complete:
                seen[key] = ref
            indices.append(item)
            batch_id = meta.get("batch_digest")
            if batch_id and meta.get("tool") in {"http_request", "http_batch_manifest", "path_dictionary_manifest", "path_dictionary_expansion", "http_batch_terminal"}:
                batch = batches.setdefault(batch_id, {"batch_digest": batch_id, "planned": None, "members": {}, "manifest_ref": None})
                if meta["tool"].endswith("manifest"):
                    batch["planned"] = out.get("estimated_requests")
                    batch["manifest_ref"] = ref
                elif meta["tool"] == "http_batch_terminal":
                    batch["status"] = out.get("status")
                    batch["started"] = out.get("started_requests")
                elif meta["tool"] == "path_dictionary_expansion":
                    batch["planned"] = (batch["planned"] or 0) + out["estimated_requests"]
                    batch.setdefault("expansion_refs", []).append(ref)
                elif meta.get("ordinal") is not None:
                    batch["members"][meta["ordinal"]] = out
        # Missing/partial results and observed response differences precede recency.
        def priority(item):
            out = item.get("output", {})
            incomplete = any(out.get(k) for k in ("timed_out", "truncated", "output_incomplete", "outcome_unknown"))
            groups = out.get("groups") or []
            return (incomplete, len(groups) > 1, item.get("source_sequence") or 0)
        indices = sorted(reversed(indices), key=priority, reverse=True)
        page, size = [], 0
        for item in indices[offset:offset + limit]:
            encoded_size = len(json.dumps(item, ensure_ascii=False))
            if encoded_size > 6000:
                item = {k: item.get(k) for k in ("evidence_ref", "tool", "target", "input_digest", "resource_generation", "source_sequence")}
                item["detail_availability"] = "read_full_evidence"
                encoded_size = len(json.dumps(item, ensure_ascii=False))
            if page and size + encoded_size > 16_000:
                break
            page.append(item)
            size += encoded_size
        coverage = []
        for batch in list(batches.values())[-12:]:
            members = batch.pop("members")
            groups = {}
            failures = 0
            cancelled = 0
            timed_out = 0
            for ordinal, out in members.items():
                cancelled += out.get("outcome") in {"stopped", "interrupted", "cancelled"}
                timed_out += out.get("outcome") in {"timeout", "timed_out", "read_timeout", "connect_timeout"}
                key = (out.get("status_code"), out.get("body_sha256"))
                group = groups.setdefault(key, {"status_code": key[0], "body_sha256": key[1], "count": 0, "sample_ordinals": []})
                group["count"] += 1
                if len(group["sample_ordinals"]) < 3:
                    group["sample_ordinals"].append(ordinal)
                failures += out.get("outcome") not in (None, "response", "stopped", "interrupted", "cancelled")
            coverage.append({**batch, "landed_results": len(members), "transport_failures": failures,
                "cancelled": cancelled, "timed_out": timed_out,
                "not_started": max(0, batch["planned"] - batch["started"]) if batch["planned"] is not None and batch.get("started") is not None else None,
                "not_finished": max(0, batch["planned"] - len(members) + cancelled) if batch["planned"] is not None else None,
                "response_groups": list(groups.values())[:12], "group_count": len(groups),
                "groups_omitted": max(0, len(groups) - 12),
                "coverage_note": "Counts cover durable per-request records, including interruption records, not just received responses. Timeout is a subset of transport failures. Display/read coverage is separate. Full members are in referenced experiments."})
        return {"experiments": page, "total": len(indices), "resource_generation": generation,
                "batch_coverage": coverage, "batch_count": len(batches), "batch_coverage_omitted": max(0, len(batches) - len(coverage)),
                "next_offset": offset + len(page) if offset + len(page) < len(indices) else None,
                "evidence_refs": [x["evidence_ref"] for x in page],
                "history_access": "Use evidence_search and evidence_read for complete inputs, outputs and older records.",
                "interpretation": "Execution records, not conclusions. Historical environments require revalidation; identical tests may be repeated when conditions or purpose change."}
