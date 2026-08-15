"""Static contract checks for the test-only Chinese runtime workbench."""

from __future__ import annotations

from pathlib import Path


WEB_ROOT = Path(__file__).parents[1] / "scripts" / "runtime_web"


def test_workbench_has_chinese_three_panel_contract() -> None:
    html = (WEB_ROOT / "index.html").read_text(encoding="utf-8")
    assert 'lang="zh-CN"' in html
    for required_id in (
        "agent-tree",
        "chief-agent-button",
        "conversation-stream",
        "details-content",
        "new-messages-button",
        "history-button",
        "tooltip-layer",
        "run-status",
        "event-sequence",
    ):
        assert f'id="{required_id}"' in html
    assert 'class="statusbar"' in html
    for detail_tab in ("overview", "prompt", "memory", "report", "runtime"):
        assert f'data-detail-tab="{detail_tab}"' in html
    for obsolete in ("state-drawer", "activity-filter", 'class="grain"', "titlebar"):
        assert obsolete not in html
    for removed_control in ("pause-button", "follow-button", "jump-button"):
        assert f'id="{removed_control}"' not in html


def test_workbench_frontend_keeps_agent_hierarchy_history_and_conversation_rules() -> None:
    app = (WEB_ROOT / "app.js").read_text(encoding="utf-8")
    css = (WEB_ROOT / "styles.css").read_text(encoding="utf-8")
    for required in (
        "challengeAgents",
        "chiefAgent",
        "executionChildren",
        "switchAgent",
        "buildConversationItems",
        "buildRawConversation",
        "flushToolGroup",
        "renderToolGroup",
        "toolRows",
        "toolFailed",
        "expandedToolGroups",
        "expandedToolCalls",
        "test_effective_prompt",
        "tool_call_id",
        "detailHasMore",
        "scrollByAgent",
        "unreadByAgent",
        "requestToken",
        "renderRuntime",
        "makeAgentIcon",
        "makeSecaiIcon",
        "makeCopyButton",
        "writeClipboard",
        "iconStatus",
        "challengeForAgent",
        "agentIconStatus",
        "chiefOverviewStats",
        "operationResultData",
        "runtimeDuration",
        "compareAgentStart",
        "executionStatusRank",
        "compareExecutionAgents",
        "challengeStatusRank",
        "compareChallengeAgents",
        "agentStartLabel",
        "executionAgentName",
        "started_at",
        "setupPaneResizers",
        "paneWidthBounds",
        "ArrowLeft",
        "ArrowRight",
        'conversation-stream").addEventListener("scroll',
        'status === "completed"',
        'if (content) {',
        'if (content) {\n          flushToolGroup();',
        'kind: "answer"',
        'kind: "tool_group"',
        'kind: "report"',
        'item.events, item.sequenceStart, item.sequenceEnd',
        'dataset.sequenceStart',
        'dataset.sequenceEnd',
    ):
        assert required in app
    assert 'agent.parent_id === parentId' in app
    assert '.sort(compareExecutionAgents)' in app
    assert 'if (["running", "working", "active"].includes(status)) return 0;' in app
    assert 'if (["queued", "pending", "starting"].includes(status)) return 1;' in app
    assert '.sort(compareChallengeAgents)' in app
    assert 'if (["running", "working", "active", "waiting"].includes(status)) return 0;' in app
    assert 'return compareAgentStart(left, right);' in app
    assert 'latestAgentActivity(right) - latestAgentActivity(left)' not in app
    assert "grid-template-columns: var(--left-width) minmax(var(--min-center-width), 1fr) var(--right-width)" in css
    assert "height: 100vh" in css
    assert ".conversation-stream" in css
    assert ".chief-dock" in css
    assert ".execution-agent-row.completed" in css
    assert ".execution-copy strong" in css
    assert ".conversation-timeline" in css
    assert "timeline-node" in app
    assert ".tool-activity-group" in css
    assert ".tool-activity-head" in css
    assert ".tool-event-icon" in css
    assert ".tool-row" in css
    assert ".tool-row-detail-shell" in css
    assert ".tool-detail" in css
    assert ".agent-icon-challenge" in css
    assert ".agent-icon-execution" in css
    assert ".agent-icon-chief" in css
    assert ".agent-icon.status-active" in css
    assert ".agent-icon.status-completed" in css
    assert ".agent-icon.status-error" in css
    assert 'agent?.role !== "execution" || status !== "error"' in app
    assert '["stopped", "closed", "terminated", "exited"].includes(containerStatus)' in app
    assert 'return "muted"' in app
    assert '["pending", "queued", "starting", "waiting", "blocked", "stopping"]' in app
    assert 'if (agent?.role === "challenge" && status === "muted")' in app
    assert 'controller_cursor' not in (WEB_ROOT / "server.py").read_text(encoding="utf-8")
    assert 'operation.operation_type === "benchmark_submit_flag"' in app
    assert 'cumulative_score' in app
    assert '"提交 Flag"' in app
    assert '"获得分数"' in app
    assert '"已运行时长"' in app
    assert 'if (agent.role === "chief" || agent.role === "challenge")' in app
    assert 'return `${minutes} 分钟`;' in app
    assert "function timestampDate(value)" in app
    assert '`${text.replace(" ", "T")}Z`' in app
    assert 'stat.dataset.runtimeDuration = "true"' in app
    assert "refreshRuntimeDuration()" in app
    for tool_name in (
        "challenge_get_state",
        "challenge_wait_for_state",
        "chief_get_core_state",
        "execution_get_assignment",
        "skill_read",
        "system_http_request",
        "system_web_fingerprint",
        "tool_result_read",
    ):
        assert f"{tool_name}:" in app
    assert 'target ? `${toolDisplayName(name)}：${target}` : toolDisplayName(name)' in app
    assert 'make("small", "", name)' in app
    assert "/assets/Challenge.svg" in css
    assert "/assets/Execution.svg" in css
    assert "/assets/Chief.svg" in css
    assert ".copy-button" in css
    assert "Exec Agent." in app
    assert 'if (agent?.kind === "bootstrap") return "Bootstrap";' in app
    assert 'if (agent?.kind === "exploration") return "探索";' in app
    assert 'function agentRoleLabel(agent)' in app
    assert "创建 ${clock(agent.created_at)}" in app
    assert "execution-start-time" not in app
    assert "execution-start-time" not in css
    assert "复制消息" in app
    assert "复制最终报告" in app
    assert "message-footer" in app
    assert "message-footer" in css
    assert "agent-icon-message" not in app
    assert 'make("div", "message-header")' not in app
    assert ".message-header" not in css
    assert "tool-detail-section-header" in app
    assert ".pane-resizer" in css
    assert 'data-resize="left"' in (WEB_ROOT / "index.html").read_text(encoding="utf-8")
    assert 'data-resize="right"' in (WEB_ROOT / "index.html").read_text(encoding="utf-8")
    assert ".tooltip-layer" in css
    assert "scrollbar-gutter: stable" in css
    assert "prefers-reduced-motion" in css
    assert "data-mobile-pane" in css
    assert "makeRobotIcon" not in app
    assert ".robot-icon" not in css
    assert 'agent-icon.status-active {\n  animation:' not in css
    assert "expandedTools" not in app
    assert "expandedProcessing" not in app
    assert "renderToolActivityGroup" not in app
    assert "renderProcessingGroup" not in app
    assert "renderStandaloneProcessing" not in app
    assert "renderPlanning" not in app
    assert "kind: \"planning\"" not in app
    assert "规划下一步" not in app
    assert ".planning-turn" not in css
    assert ".planning-icon" not in css
    assert "processing-summary" not in app
    assert "processing-group" not in app
    assert "processing-body" not in app
    assert "processing-summary" not in css
    assert "processing-group" not in css
    assert "processing-body" not in css
    assert "tool-event-body-shell" not in css
    assert ".tool-row.expanded" not in css
    assert 'make("button", "tool-row-head tool-event-head")' in app
    assert 'head.setAttribute("aria-expanded", String(expanded))' in app
    assert 'renderToolRow(row, groupId)' in app
    assert 'shell.classList.toggle("is-open", nextExpanded)' in app
    assert 'summary.setAttribute("aria-expanded", String(nextExpanded))' in app
    assert 'head.setAttribute("aria-expanded", String(nextExpanded))' in app
    assert "grid-template-columns: 24px minmax(0, 1fr) 14px" in css
    assert "width: 24px" in css
    assert "height: 24px" in css
    assert "transition: grid-template-rows 220ms" in css
    assert ".tool-activity-head[aria-expanded=\"true\"] > .chevron" in css
    assert 'summary.setAttribute("aria-expanded", String(expanded))' in app
    assert 'const groupId = `tool-group-${sequenceStart}-${sequenceEnd}`' in app
    assert 'wrapper.append(head, shell)' in app
    assert "pause-button" not in app
    assert "follow-button" not in app
    assert "jump-button" not in app
    assert "state.paused" not in app
    assert "toolViewModes" in app
    assert "toolBatchSelections" in app
    assert "renderToolViews" in app
    assert "renderToolSummaryView" in app
    assert "resultContentItems" in app
    assert "renderSummaryContent" in app
    assert "renderToolJsonView" in app
    assert "renderHttpView" in app
    assert "renderHttpTargetCard" in app
    assert "httpTargetItems" in app
    assert "httpRequestText" in app
    assert "httpResponseText" in app
    assert "httpResultEntries" in app
    assert "requestHeaderLines" in app
    assert "requestBodyText" in app
    assert "httpPreviewValue" in app
    assert "http-selection-list" in app
    assert "toolBatchSelections.set(callId, entry.id)" in app
    for http_field in ("request.headers", "request.cookies", "request.auth", "request.body", "request.query", "args.wait_seconds", "args.session_id"):
        assert http_field in app
    assert '[["packet", "报文"], ["json", "JSON"]]' in app
    assert '[["summary", "摘要"], ["json", "JSON"]]' in app
    assert 'setAttribute("aria-label", "HTTP 请求或响应列表")' in app
    assert ".tool-view-tabs" in css
    assert ".tool-summary-grid" in css
    assert ".tool-summary-content-pre" in css
    assert ".http-target-card" in css
    assert ".http-target-url" in css
    assert ".http-packet-pre" in css
    assert ".http-selection-list" in css
    assert "max-height: 380px" in css
    assert "truncated === true" in app
    assert "eof === false" in app


def test_workbench_uses_safe_dom_rendering_and_removes_obsolete_event_ui() -> None:
    app = (WEB_ROOT / "app.js").read_text(encoding="utf-8")
    css = (WEB_ROOT / "styles.css").read_text(encoding="utf-8")
    assert ".innerHTML" not in app
    assert "textContent" in app
    assert "renderStructuredText" in app
    assert "activity-filter" not in app
    assert "state-drawer" not in app
    assert "folder-glyph" not in app
    assert "orphan-process-turn" not in app
    assert "orphan-process-turn" not in css
    assert "orphan-process-turn::before" not in css
    assert 'chief-avatar">A' not in (WEB_ROOT / "index.html").read_text(encoding="utf-8")
    assert ".activity-list" not in css
    assert ".statusbar" in css
    assert "titlebar" not in css


def test_workbench_sidebar_can_collapse_selected_challenge_and_logs_transitions() -> None:
    app = (WEB_ROOT / "app.js").read_text(encoding="utf-8")
    server = (WEB_ROOT / "server.py").read_text(encoding="utf-8")

    assert "const expanded = state.expandedChallengeAgents.has(agent.agent_id);" in app
    assert "state.expandedChallengeAgents.delete(agent.agent_id)" in app
    assert 'uiLog("info", "challenge_tree_toggle"' in app
    assert 'uiLog("debug", "agent_detail_request"' in app
    assert 'uiLog("warn", "snapshot_poll_failed"' in app
    assert 'uiLog("error", "unhandled_rejection"' in app
    assert '"monitor_started run_id=%s database=%s address=%s"' in server
    assert 'LOGGER.info(\n                    "http_request' in server
    assert 'LOGGER.warning(\n                    "monitor_refresh_failed' in server


def test_quick_runtime_prompt_is_target_driven() -> None:
    from scripts import quick_runtime_test as quick

    prompt = quick._prompt(
        [
            {
                "name": "web",
                "unique_code": "web",
                "address": "http://127.0.0.1:8080",
                "mission": "inspect the configured service",
            }
        ]
    )
    assert "http://127.0.0.1:8080" in prompt
    assert "start targets" in prompt
    assert "submit flags" in prompt
    assert "real work" in prompt
