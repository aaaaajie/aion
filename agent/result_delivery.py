"""Durable, scope-bound delivery of new tool-result pages to the model."""

from copy import deepcopy
import json
import hashlib
from uuid import uuid4

from sqlalchemy import select

from agent.state.models import StateEventRecord


class ResultDelivery:
    def __init__(self, store, scope):
        self.store, self.scope = store, scope
        self.pending = {}

    async def restore(self):
        async with self.store.service.db.sessions() as session:
            rows = (await session.scalars(select(StateEventRecord).where(
                StateEventRecord.run_id == self.store.run_id,
                StateEventRecord.agent_id == self.store.agent_id,
                StateEventRecord.event_type.in_({"tool_result_delivery_pending", "tool_result_delivery_confirmed"}),
            ).order_by(StateEventRecord.sequence))).all()
        for row in rows:
            p = row.payload
            if p.get("scope") != self.scope:
                continue
            key = p["delivery_key"]
            if row.event_type == "tool_result_delivery_pending":
                self.pending[key] = deepcopy(p)
                if p.get("reasoning_required"):
                    self.pending[key]["messages"][0]["reasoning_content"] = ""
            else:
                self.pending.pop(key, None)

    def inject(self, messages):
        """Replace the existing exchange atomically; never duplicate tool replies."""
        if not self.pending:
            return messages
        kept = list(messages)
        for pending in self.pending.values():
            group = pending["messages"]
            call_ids = [m["tool_call_id"] for m in group[1:]]
            for index in range(len(kept) - 1, -1, -1):
                if kept[index].get("role") != "assistant" or kept[index].get("tool_calls") != group[0].get("tool_calls"):
                    continue
                replies = kept[index + 1:index + len(group)]
                if [m.get("tool_call_id") for m in replies] == call_ids:
                    kept[index:index + len(group)] = deepcopy(group)
                    break
            else:
                kept.extend(deepcopy(group))
        return kept

    async def add(self, assistant, results, events):
        if not results:
            return
        key = uuid4().hex
        pages = []
        for event, message in zip(events, results, strict=True):
            decoded = json.loads(message["content"])
            data = decoded.get("data") or {}
            if not isinstance(data, dict):
                data = {}
            content = data.get("content")
            included = isinstance(content, str) or not decoded.get("truncated")
            full = included and not decoded.get("truncated") and not decoded.get("result_ref")
            offset = data.get("offset", data.get("offset_bytes", data.get("cursor", 0)))
            unit = "bytes" if "offset_bytes" in data else "cursor" if "cursor" in data else "characters"
            end = data.get("next_cursor") if unit == "cursor" else offset + data.get("bytes_returned", 0) if unit == "bytes" else offset + len(content) if isinstance(content, str) and isinstance(offset, int) else None
            page = {"sequence": event.sequence, "tool_call_id": message["tool_call_id"],
                "result_ref": decoded.get("result_ref") or decoded.get("source_result_ref") or data.get("result_ref"),
                "evidence_ref": data.get("evidence_ref"), "report_ref": data.get("report_ref"),
                "evidence_refs": data.get("evidence_refs", decoded.get("evidence_refs", [])),
                "content_included": included, "presentation_complete": full,
                "offset": offset, "end": end, "unit": unit,
                "source_eof": data.get("eof"), "source_next_offset": data.get("next_offset")}
            decoded.update(delivery_key=key, content_included=included, presentation_complete=full,
                           delivery_range={k: page[k] for k in ("offset", "end", "unit", "source_eof", "source_next_offset")})
            message["content"] = json.dumps(decoded, ensure_ascii=False, separators=(",", ":"))
            pages.append(page)
        payload = {"delivery_key": key, "scope": self.scope, "pages": pages,
                   "messages": [deepcopy(assistant), *deepcopy(results)]}
        durable = deepcopy(payload)
        durable["reasoning_required"] = "reasoning_content" in durable["messages"][0]
        durable["messages"][0].pop("reasoning_content", None)
        for call in durable["messages"][0].get("tool_calls", []):
            fn = call.get("function") or {}
            if fn.get("name") in {"solver_submit_flag", "worker_report", "worker_update"}:
                try:
                    args = json.loads(fn["arguments"])
                except (ValueError, KeyError):
                    continue
                for field in ("flag", "candidate_flag"):
                    value = args.pop(field, None)
                    if isinstance(value, str) and value:
                        args[field + "_sha256"] = hashlib.sha256(value.encode()).hexdigest()
                fn["arguments"] = json.dumps(args, ensure_ascii=False)
        await self.store.append_event("tool_result_delivery_pending", durable)
        self.pending[key] = payload

    async def defer_content(self):
        """Keep source cursors truthful when even protected pages exceed hard capacity."""
        for p in self.pending.values():
            for page, message in zip(p["pages"], p["messages"][1:], strict=True):
                decoded = json.loads(message["content"])
                data = decoded.get("data") or {}
                # Durable source references are required before omitting content.
                if not (page["result_ref"] or page["evidence_ref"] or page["report_ref"] or page["evidence_refs"]):
                    continue
                decoded = {"ok": decoded.get("ok"), "delivery_key": p["delivery_key"], "content_included": False,
                    "presentation_complete": False, "delivery_deferred": "model_hard_capacity",
                    "result_ref": page["result_ref"], "data": {
                        k: data[k] for k in ("evidence_ref", "report_ref", "evidence_refs", "offset", "next_offset", "eof")
                        if isinstance(data, dict) and k in data},
                    "evidence_refs": page["evidence_refs"],
                    "unpresented_range": {k: page[k] for k in ("offset", "end")}}
                message["content"] = json.dumps(decoded, ensure_ascii=False)
                page.update(content_included=False, presentation_complete=False)
            await self.store.append_event("tool_result_delivery_deferred", {
                "delivery_key": p["delivery_key"], "scope": self.scope, "pages": p["pages"]})

    async def confirm(self, request_messages):
        visible = {(m.get("tool_call_id"), m.get("content")) for m in request_messages if m.get("role") == "tool"}
        for key, p in list(self.pending.items()):
            if not all((m["tool_call_id"], m["content"]) in visible for m in p["messages"][1:]):
                continue
            await self.store.append_event("tool_result_delivery_confirmed", {
                "delivery_key": key, "scope": self.scope, "pages": p["pages"],
                "result_sequences": [x["sequence"] for x in p["pages"] if x["presentation_complete"]],
                "meaning": "Presented in a model request with a valid non-truncated response; not semantic adoption."})
            self.pending.pop(key)

    async def present(self, request_messages, *, attempt):
        """Record request inclusion separately from acknowledgment and adoption."""
        visible = {(m.get("tool_call_id"), m.get("content")) for m in request_messages if m.get("role") == "tool"}
        for key, pending in self.pending.items():
            if all((m["tool_call_id"], m["content"]) in visible for m in pending["messages"][1:]):
                await self.store.append_event("tool_result_delivery_presented", {
                    "delivery_key": key, "scope": self.scope, "pages": pending["pages"],
                    "attempt": attempt, "confirmed": False,
                })
