"""Short current-session adoption phase, preemptible by stop and rotation."""

import asyncio
from copy import deepcopy
import json

from agent.state.schemas import CapabilityContext

READ_TOOLS = {"evidence_read", "tool_result_read", "system_http_output", "system_http_response", "system_task_output", "system_network_output"}


async def run_progress_check(runner, store, client, messages):
    if runner.role != "solver" or not runner.registry.has_tool("solver_review"):
        return messages
    ctx = CapabilityContext(run_id=store.run_id, agent_id=store.agent_id, role="solver", unique_code=runner._unique_code)
    policy = runner.settings.stagnation_policy
    check = await store.service.begin_progress_check(store.run_id, ctx,
        interval_seconds=policy.review_after_seconds / 2, rotate_after_seconds=policy.rotate_after_seconds)
    if check is None:
        return messages
    started = asyncio.get_running_loop().time()
    result = {"check_key": check["check_key"], "scope": check["scope"], "status": "failed", "requests": 0,
              "reason": "missing_review"}
    working = [*messages, {"role": "user", "content": (
        "<progress_adoption>Bounded adoption check: decide whether these completed, delivered executions contain new information. "
        "Call solver_review with validated new_information, no_new_information, or inconclusive. "
        "Reading integrity is not proof of a vulnerability. No new experiments. The runtime binds strategy_revision; omit that argument. "
        "Your conclusion is current-strategy reasoning, not a shared fact.\n" + json.dumps(check, ensure_ascii=False) + "</progress_adoption>")}]
    try:
        async with asyncio.timeout(check["timeout_seconds"]):
            for attempt in range(2):
                if runner._strategy_reset_pending or runner.registry.admission_closed:
                    result.update(status="interrupted", reason="scope_changed")
                    break
                allowed = {"solver_review"} | (READ_TOOLS if attempt == 0 else set())
                definitions = []
                for name in sorted(allowed):
                    spec = runner.registry.get(name)
                    if not spec:
                        continue
                    definition = deepcopy(spec.definition())
                    if name == "solver_review":
                        schema = definition["function"]["parameters"]
                        schema["properties"].pop("strategy_revision", None)
                        schema["required"] = [x for x in schema.get("required", []) if x != "strategy_revision"]
                    definitions.append(definition)
                result["requests"] += 1
                payload = await runner._request_completion(client, working, tool_definitions=definitions, max_attempts=1)
                choice = runner._response_choice(payload)
                if choice.get("finish_reason") not in {"stop", "tool_calls"}:
                    result["reason"] = "completion_truncated"
                    break
                message = choice["message"]
                if runner._requires_reasoning_content() and message.get("tool_calls") and not isinstance(runner._reasoning_content(message), str):
                    result["reason"] = "invalid_llm_response"
                    break
                calls = deepcopy(message.get("tool_calls") or [])
                names = [c.get("function", {}).get("name") for c in calls]
                if not calls or any(name not in allowed for name in names) or ("solver_review" in names and len(calls) != 1):
                    result["reason"] = "check_tool_contract"
                    break
                # Reject a late response before executing even a read operation.
                state = await store.service.get_agent_runtime(store.run_id, store.agent_id)
                challenge = (await store.service.get_overview(store.run_id, unique_code=runner._unique_code))["challenges"][0]
                if runner._strategy_reset_pending or runner.registry.admission_closed or state["agent"]["status"] != "running" or state["agent"]["resource_generation"] != check["scope"]["generation"] or challenge["strategy_revision"] != check["scope"]["strategy_revision"] or challenge["work_status"] != "active" or challenge["stagnation_stage"] == "rotation_due":
                    result.update(status="interrupted", reason="scope_changed")
                    break
                for c in calls:
                    name = c["function"]["name"]
                    args = json.loads(c["function"]["arguments"])
                    if name == "solver_review":
                        if "strategy_revision" in args:
                            raise ValueError("strategy_revision is runtime-owned in adoption mode")
                        args["strategy_revision"] = check["scope"]["strategy_revision"]
                        c["function"]["arguments"] = json.dumps(args, ensure_ascii=False)
                    elif name.startswith("system_"):
                        executions = (await store.service.solver_review_state(store.run_id, store.agent_id))["execution"]
                        identity = "interaction_id" if name.startswith("system_http_") else "task_id"
                        tasks = executions.get("completed_tasks", [])
                        if not any(t.get(identity) == args.get(identity) and t.get("status") == "completed" for t in tasks):
                            raise ValueError("adoption_read_requires_owned_completed_result")
                        if "wait_seconds" in runner.registry.get(name).input_model.model_fields:
                            args["wait_seconds"] = 0
                        c["function"]["arguments"] = json.dumps(args, ensure_ascii=False)
                assistant = {"role": "assistant", "content": message.get("content") or "", "tool_calls": calls}
                if message.get("reasoning_content") is not None:
                    assistant["reasoning_content"] = message["reasoning_content"]
                await runner._result_delivery.confirm(working)
                await store.append_event("assistant_response", {"phase": "progress_adoption", "tool_names": names,
                    "check_key": check["check_key"], "finish_reason": choice["finish_reason"]})
                runner._last_assistant_message = assistant
                working.append(assistant)
                # Expose only the specific allowed tools being executed, retaining the normal discovery policy.
                for c in calls:
                    runner.registry.expose_tool(c["function"]["name"])
                responses, _ = await runner._execute_tool_calls(
                    store, calls, round_number=runner._current_round_number, allow_worker_dispatch=False)
                working.extend(responses)
                if "solver_review" in names:
                    outcome = json.loads(responses[0]["content"])
                    result.update(status="completed" if outcome.get("ok") else "failed",
                                  reason="review_recorded" if outcome.get("ok") else (outcome.get("error") or {}).get("code", "review_rejected"),
                                  assessment=args.get("assessment"))
                    break
    except TimeoutError:
        result.update(status="timeout", reason="check_deadline")
    except asyncio.CancelledError:
        result.update(status="interrupted", reason="cancelled")
        raise
    except Exception as exc:
        result.update(reason=getattr(exc, "code", type(exc).__name__))
    finally:
        result["duration_ms"] = int((asyncio.get_running_loop().time() - started) * 1000)
        await store.append_event("solver_progress_check_finished", result)
    return runner._result_delivery.inject(working)
