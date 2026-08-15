(() => {
  "use strict";

  const TERMINAL = new Set(["completed", "failed", "stopped", "cancelled", "interrupted"]);
  const ACTIVE = new Set(["pending", "queued", "starting", "running", "waiting", "working", "blocked", "stopping"]);
  const ACTIVE_CHALLENGE_WORK = new Set(["active", "warning", "extended"]);
  const CONVERSATION_EVENTS = new Set(["assistant_response", "tool_call", "tool_result", "agent_report"]);
  const ROLE_NAMES = { chief: "首席 Agent", challenge: "挑战 Agent", execution: "执行 Agent" };
  const STATUS_NAMES = {
    active: "活跃",
    pending: "待处理",
    queued: "排队中",
    starting: "启动中",
    running: "运行中",
    waiting: "等待状态变更",
    working: "工作中",
    blocked: "已阻塞",
    stopping: "停止中",
    completed: "已完成",
    failed: "失败",
    stopped: "已停止",
    cancelled: "已取消",
    interrupted: "已中断",
    indeterminate: "待确认",
    started: "已开始",
    success: "成功",
    verified: "已验证",
    warning: "警告",
    extended: "已延长",
    paused: "已暂停",
    closed: "已关闭",
    unassigned: "未分配",
  };
  const PHASE_NAMES = { early: "早期", mid: "中期", late: "后期" };
  const TOOL_LABELS = {
    system_shell: "执行命令",
    system_read_file: "读取文件",
    system_write_file: "写入文件",
    system_edit_file: "编辑文件",
    system_list_directory: "浏览目录",
    system_glob: "查找文件",
    system_grep: "搜索内容",
    system_create_directory: "创建目录",
    system_delete_path: "删除路径",
    system_task_output: "获取后台任务输出",
    system_task_stop: "停止后台任务",
    benchmark_list_challenges: "刷新挑战目录",
    benchmark_start_challenge: "启动挑战",
    benchmark_get_hint: "获取提示",
    benchmark_submit_flag: "提交 Flag",
    benchmark_close_challenge: "关闭挑战",
    chief_create_challenge_agent: "创建挑战 Agent",
    chief_get_challenge_reports: "读取挑战报告",
    chief_get_core_state: "读取核心状态",
    chief_get_schedule: "读取任务排期",
    chief_refresh_challenges: "刷新挑战目录",
    chief_request_hint: "申请挑战提示",
    chief_wait_for_state: "等待全局状态",
    challenge_advance_cycle: "推进分析周期",
    challenge_begin_cycle: "开始分析周期",
    challenge_close_challenge: "关闭挑战",
    challenge_commit_cycle: "提交分析周期",
    challenge_create_execution_agent: "创建执行 Agent",
    challenge_get_execution_reports: "读取执行报告",
    challenge_get_state: "读取挑战状态",
    challenge_get_updates: "读取协作更新",
    challenge_report_status: "报告挑战状态",
    challenge_start_cycle: "启动分析周期",
    challenge_submit_analysis_plan: "提交分析计划",
    challenge_submit_flag: "提交候选 Flag",
    challenge_wait_for_state: "等待挑战状态",
    execution_get_assignment: "读取执行任务",
    execution_update_progress: "更新执行进度",
    execution_report: "提交执行报告",
    skill_invoke: "调用技能",
    skill_list: "列出技能",
    skill_read: "读取技能说明",
    skill_resource_read: "读取技能资源",
    skill_search: "搜索技能",
    system_http_analyze: "分析 HTTP 响应",
    system_http_cleanup: "清理 HTTP 任务",
    system_http_output: "获取 HTTP 输出",
    system_http_probe: "探测 HTTP 服务",
    system_http_request: "发起 HTTP 请求",
    system_http_response: "读取 HTTP 响应",
    system_http_stop: "停止 HTTP 任务",
    system_web_fingerprint: "识别 Web 服务",
    system_web_path_probe: "探测 Web 路径",
    tool_result_read: "读取工具结果",
  };

  const state = {
    snapshot: null,
    events: [],
    afterSequence: 0,
    selectedAgent: null,
    expandedChallengeAgents: new Set(),
    selectedDetail: null,
    detailBefore: 0,
    detailHasMore: false,
    detailTab: "overview",
    detailTabScroll: new Map(),
    expandedToolGroups: new Set(),
    expandedToolCalls: new Set(),
    toolViewModes: new Map(),
    toolBatchSelections: new Map(),
    toolScrollPositions: new Map(),
    scrollByAgent: new Map(),
    unreadByAgent: new Map(),
    pendingScrollRestore: false,
    follow: true,
    requestToken: 0,
    detailController: null,
    loadingAgentId: null,
    loadingOlder: false,
  };

  const UI_LOG_PREFIX = "[AION UI]";
  let lastPollError = null;
  let lastPollErrorAt = 0;

  function uiLog(level, event, details = {}) {
    const method = typeof console?.[level] === "function" ? console[level] : console.log;
    method.call(console, `${UI_LOG_PREFIX} ${event}`, {
      at: new Date().toISOString(),
      ...details,
    });
  }

  const $ = (selector) => document.querySelector(selector);

  function make(tag, className, value) {
    const element = document.createElement(tag);
    if (className) element.className = className;
    if (value !== undefined && value !== null) element.textContent = String(value);
    return element;
  }

  function setText(selector, value, fallback = "—") {
    const element = $(selector);
    if (!element) return;
    element.textContent = value === undefined || value === null || value === "" ? fallback : String(value);
  }

  function pretty(value) {
    if (value === undefined || value === null) return "—";
    if (typeof value === "string") return value;
    try {
      return JSON.stringify(value, null, 2);
    } catch (_) {
      return String(value);
    }
  }

  function copyText(value) {
    return typeof value === "string" ? value : pretty(value);
  }

  async function writeClipboard(value) {
    try {
      if (navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(value);
        return true;
      }
    } catch (_) {
      // Fall through to the legacy local-document copy path.
    }
    const textarea = make("textarea");
    textarea.value = value;
    textarea.setAttribute("readonly", "");
    textarea.style.position = "fixed";
    textarea.style.opacity = "0";
    document.body.append(textarea);
    textarea.select();
    let copied = false;
    try {
      copied = document.execCommand("copy");
    } catch (_) {
      copied = false;
    }
    textarea.remove();
    return copied;
  }

  function short(value, length = 32) {
    const text = value === undefined || value === null ? "—" : String(value);
    return text.length > length ? `${text.slice(0, Math.max(1, length - 1))}…` : text;
  }

  function statusLabel(value) {
    const text = String(value || "");
    return STATUS_NAMES[text.toLowerCase()] || text || "未知";
  }

  function phaseLabel(value) {
    const text = String(value || "");
    return PHASE_NAMES[text.toLowerCase()] || text || "—";
  }

  function dateValue(value) {
    const parsed = timestampDate(value);
    return parsed ? parsed.getTime() : 0;
  }

  function timestampDate(value) {
    if (!value) return null;
    if (value instanceof Date) return Number.isNaN(value.getTime()) ? null : value;
    const text = String(value).trim();
    if (!text) return null;
    const hasTimezone = /(?:Z|[+-]\d{2}:?\d{2})$/i.test(text);
    const normalized = !hasTimezone && /^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}/.test(text)
      ? `${text.replace(" ", "T")}Z`
      : text;
    const parsed = new Date(normalized);
    return Number.isNaN(parsed.getTime()) ? null : parsed;
  }

  function clock(value) {
    if (!value) return "—";
    const date = timestampDate(value);
    if (!date) return short(value, 18);
    return date.toLocaleTimeString("zh-CN", {
      hour12: false,
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    });
  }

  function elapsed(value) {
    const timestamp = dateValue(value);
    if (!timestamp) return "—";
    const seconds = Math.max(0, Math.floor((Date.now() - timestamp) / 1000));
    if (seconds < 60) return `${seconds} 秒前`;
    if (seconds < 3600) return `${Math.floor(seconds / 60)} 分钟前`;
    if (seconds < 86400) return `${Math.floor(seconds / 3600)} 小时前`;
    return `${Math.floor(seconds / 86400)} 天前`;
  }

  function runtimeDuration(agent, challenge) {
    const startedAt = dateValue(agent?.started_at) || dateValue(challenge?.started_at) || dateValue(agent?.created_at);
    if (!startedAt) return "—";
    const status = String(agent?.status || "").toLowerCase();
    const workStatus = String(challenge?.work_status || "").toLowerCase();
    const finishedAt = TERMINAL.has(status) || workStatus === "closed"
      ? dateValue(agent?.ended_at) || dateValue(challenge?.updated_at) || Date.now()
      : Date.now();
    const minutes = Math.max(0, Math.floor((Math.max(startedAt, finishedAt) - startedAt) / 60_000));
    return `${minutes} 分钟`;
  }

  function stateTone(value) {
    const text = String(value || "").toLowerCase();
    if (["failed", "error", "interrupted", "indeterminate", "cancelled"].some((part) => text.includes(part))) return "bad";
    if (["queued", "pending", "starting", "stopping", "blocked", "warning", "extended", "paused"].some((part) => text.includes(part))) return "warn";
    if (["running", "working", "active", "completed", "success", "verified"].some((part) => text.includes(part))) return "good";
    return "muted";
  }

  const SVG_NS = "http://www.w3.org/2000/svg";

  function svgPart(tag, attributes = {}) {
    const element = document.createElementNS(SVG_NS, tag);
    Object.entries(attributes).forEach(([name, value]) => element.setAttribute(name, String(value)));
    return element;
  }

  function makeAgentIcon(role = "chief", status = "muted", extraClass = "") {
    const icon = make("span", `agent-icon agent-icon-${role} status-${status} ${extraClass}`.trim());
    icon.setAttribute("aria-hidden", "true");
    return icon;
  }

  function makeSecaiIcon(kind) {
    const icon = svgPart("svg", { viewBox: "0 0 24 24", focusable: "false", "aria-hidden": "true" });
    icon.classList.add("secai-icon");
    const paths = {
      copy: [
        ["rect", { x: 8, y: 8, width: 11, height: 11, rx: 2 }],
        ["path", { d: "M16 8V6a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v8a2 2 0 0 0 2 2h2" }],
      ],
      terminal: [
        ["rect", { x: 3, y: 4, width: 18, height: 16, rx: 2 }],
        ["path", { d: "m7 9 3 3-3 3M13 15h4" }],
      ],
      read: [
        ["path", { d: "M6 3h8l4 4v14H6z" }],
        ["path", { d: "M14 3v5h5M9 12h6M9 16h6" }],
      ],
      edit: [
        ["path", { d: "M4 20h4L19 9a2.1 2.1 0 0 0-3-3L5 17z" }],
        ["path", { d: "m14 7 3 3" }],
      ],
      search: [
        ["circle", { cx: 10.5, cy: 10.5, r: 6.5 }],
        ["path", { d: "m16 16 5 5" }],
      ],
      agent: [
        ["rect", { x: 5, y: 6, width: 14, height: 14, rx: 3 }],
        ["path", { d: "M12 3v3M9 12h.01M15 12h.01M9 16h6" }],
      ],
      check: [
        ["circle", { cx: 12, cy: 12, r: 9 }],
        ["path", { d: "m8 12 2.7 2.7L16.5 9" }],
      ],
      task: [
        ["rect", { x: 5, y: 4, width: 14, height: 16, rx: 2 }],
        ["path", { d: "M9 9h6M9 13h6M9 17h4" }],
      ],
      tool: [
        ["path", { d: "M14.7 6.3a4 4 0 0 0-5.4 5.4L4 17a2.1 2.1 0 0 0 3 3l5.3-5.3a4 4 0 0 0 5.4-5.4l-2.2 2.2-2.3-.7-.7-2.3z" }],
      ],
    };
    (paths[kind] || paths.tool).forEach(([tag, attributes]) => icon.append(svgPart(tag, attributes)));
    return icon;
  }

  function makeCopyButton(label, value) {
    const button = make("button", "copy-button");
    button.type = "button";
    button.setAttribute("aria-label", label);
    button.dataset.tooltip = label;
    button.append(makeSecaiIcon("copy"));
    button.addEventListener("click", async (event) => {
      event.preventDefault();
      event.stopPropagation();
      const text = copyText(typeof value === "function" ? value() : value);
      if (!text || text === "—") return;
      const copied = await writeClipboard(text);
      button.classList.toggle("copied", copied);
      button.dataset.tooltip = copied ? "已复制" : "复制失败";
      button.setAttribute("aria-label", copied ? "已复制" : "复制失败");
      window.setTimeout(() => {
        if (!button.isConnected) return;
        button.classList.remove("copied");
        button.dataset.tooltip = label;
        button.setAttribute("aria-label", label);
      }, 1400);
    });
    return button;
  }

  function iconStatus(value) {
    const text = String(value || "").toLowerCase();
    if (["failed", "error"].some((part) => text.includes(part))) return "error";
    if (["running", "working", "active"].some((part) => text === part)) return "active";
    if (["pending", "queued", "starting", "waiting", "blocked", "stopping"].some((part) => text === part)) return "pending";
    if (text === "completed") return "completed";
    return "muted";
  }

  function challengeForAgent(agent) {
    if (!agent?.unique_code) return null;
    return (state.snapshot?.challenges || []).find((challenge) => challenge.unique_code === agent.unique_code) || null;
  }

  function challengeMachineActive(agent) {
    const challenge = challengeForAgent(agent);
    const containerStatus = String(challenge?.container_status || "").toLowerCase();
    const released = challenge?.slot_occupied === false || ["stopped", "closed"].includes(containerStatus);
    const agentStatus = String(agent?.status || "").toLowerCase();
    return Boolean(
      agent?.role === "challenge"
      && !released
      && !challenge?.is_completed
      && (
        ACTIVE_CHALLENGE_WORK.has(String(challenge?.work_status || "").toLowerCase())
        || ["running", "working", "active"].includes(agentStatus)
      ),
    );
  }

  function challengeMachineLabel(challenge) {
    if (!challenge) return "机器状态未知";
    const workStatus = String(challenge.work_status || "").toLowerCase();
    if (challenge.slot_occupied === true && ACTIVE_CHALLENGE_WORK.has(workStatus)) return "机器执行中";
    if (challenge.slot_occupied === true && workStatus === "paused") return "机器已占用 · 已暂停";
    if (challenge.slot_occupied === true) return "机器已占用";
    return "机器已释放";
  }

  function agentIconStatus(agent) {
    const status = iconStatus(agent?.status);
    if (challengeMachineActive(agent) && !TERMINAL.has(String(agent?.status || "").toLowerCase())) {
      // A Challenge Agent can be waiting while its child Execution Agents work.
      // The icon represents the challenge machine, so use the persisted machine
      // state instead of turning the occupied machine gray.
      return "active";
    }
    if (agent?.role === "challenge" && status === "muted") {
      const challenge = challengeForAgent(agent);
      const containerStatus = String(challenge?.container_status || "").toLowerCase();
      const occupied = challenge?.slot_occupied !== false && !["stopped", "closed"].includes(containerStatus);
      if (occupied && !challenge?.is_completed) return "pending";
    }
    if (agent?.role !== "execution" || status !== "error") return status;
    const containerStatus = String(challengeForAgent(agent)?.container_status || "").toLowerCase();
    return ["stopped", "closed", "terminated", "exited"].includes(containerStatus) ? "muted" : status;
  }

  function numericValue(value) {
    if (value === null || value === undefined || value === "") return null;
    const number = Number(value);
    return Number.isFinite(number) ? number : null;
  }

  function operationResultData(operation) {
    const payload = operation?.result_payload;
    if (!payload || typeof payload !== "object" || Array.isArray(payload)) return {};
    return payload.data && typeof payload.data === "object" && !Array.isArray(payload.data) ? payload.data : payload;
  }

  function chiefOverviewStats() {
    const snapshot = state.snapshot || {};
    const challenges = snapshot.challenges || [];
    const flagOperations = (snapshot.operations || []).filter((operation) => operation.operation_type === "benchmark_submit_flag");
    const fallbackSubmittedFlags = challenges.reduce((total, challenge) => total + (numericValue(challenge.correct_flag_count) || 0), 0);
    const submittedFlags = flagOperations.length || fallbackSubmittedFlags;
    const cumulativeScores = flagOperations
      .map((operation) => numericValue(operationResultData(operation).cumulative_score))
      .filter((value) => value !== null);
    let score = cumulativeScores.at(-1) ?? null;
    if (score === null) {
      const awarded = flagOperations
        .map((operation) => numericValue(operationResultData(operation).awarded))
        .filter((value) => value !== null);
      if (awarded.length) score = awarded.reduce((total, value) => total + value, 0);
    }
    if (score === null) {
      const scoreSnapshot = snapshot.run?.score_snapshot || {};
      score = [scoreSnapshot.cumulative_score, scoreSnapshot.score, scoreSnapshot.total_score]
        .map(numericValue)
        .find((value) => value !== null) ?? null;
    }
    if (score === null) {
      score = challenges.reduce((total, challenge) => {
        const correct = numericValue(challenge.correct_flag_count) || 0;
        const flags = numericValue(challenge.flag_count) || 0;
        const totalScore = numericValue(challenge.total_score) || 0;
        if (!correct || !totalScore) return total;
        return total + (flags ? totalScore * Math.min(1, correct / flags) : totalScore);
      }, 0);
    }
    return { submittedFlags, score };
  }

  function isActive(agent) {
    return Boolean(agent && ACTIVE.has(agent.status));
  }

  function agentStartTimestamp(agent) {
    return dateValue(agent?.started_at) || dateValue(agent?.created_at) || Number.MAX_SAFE_INTEGER;
  }

  function agentFirstSequence(agent) {
    return state.events
      .filter((event) => event.agent_id === agent?.agent_id)
      .reduce((lowest, event) => Math.min(lowest, Number(event.sequence) || Number.MAX_SAFE_INTEGER), Number.MAX_SAFE_INTEGER);
  }

  function compareAgentStart(left, right) {
    const timeDiff = agentStartTimestamp(left) - agentStartTimestamp(right);
    if (timeDiff) return timeDiff;
    const sequenceDiff = agentFirstSequence(left) - agentFirstSequence(right);
    if (sequenceDiff) return sequenceDiff;
    return String(left.agent_id || "").localeCompare(String(right.agent_id || ""));
  }

  function executionStatusRank(agent) {
    const status = String(agent?.status || "").toLowerCase();
    if (["running", "working", "active"].includes(status)) return 0;
    if (["queued", "pending", "starting"].includes(status)) return 1;
    return 2;
  }

  function compareExecutionAgents(left, right) {
    const statusDiff = executionStatusRank(left) - executionStatusRank(right);
    if (statusDiff) return statusDiff;
    return compareAgentStart(left, right);
  }

  function challengeStatusRank(agent) {
    const status = String(agent?.status || "").toLowerCase();
    if (["running", "working", "active", "waiting"].includes(status)) return 0;
    if (["queued", "pending", "starting"].includes(status)) return 1;
    return 2;
  }

  function compareChallengeAgents(left, right) {
    const statusDiff = challengeStatusRank(left) - challengeStatusRank(right);
    if (statusDiff) return statusDiff;
    return compareAgentStart(left, right);
  }

  function agentStartLabel(agent) {
    return agent?.started_at ? `启用 ${clock(agent.started_at)}` : "待启用";
  }

  function executionAgentName(agent) {
    if (!agent?.started_at) return "Exec Agent.—.—";
    const started = timestampDate(agent.started_at);
    if (!started) return "Exec Agent.—.—";
    return `Exec Agent.${String(started.getHours()).padStart(2, "0")}.${String(started.getMinutes()).padStart(2, "0")}`;
  }

  function basename(path) {
    return String(path || "").replace(/\\/g, "/").split("/").filter(Boolean).at(-1) || "";
  }

  function mergeEvents(existing, incoming) {
    const bySequence = new Map((existing || []).map((event) => [Number(event.sequence), event]));
    (incoming || []).forEach((event) => bySequence.set(Number(event.sequence), event));
    return [...bySequence.values()].sort((left, right) => Number(left.sequence) - Number(right.sequence));
  }

  function allAgents() {
    return state.snapshot?.agents || [];
  }

  function challengeAgents() {
    return allAgents()
      .filter((agent) => agent.role === "challenge")
      .sort(compareChallengeAgents);
  }

  function chiefAgent() {
    return allAgents()
      .filter((agent) => agent.role === "chief")
      .sort((left, right) => Number(isActive(right)) - Number(isActive(left)) || dateValue(right.updated_at) - dateValue(left.updated_at))[0] || null;
  }

  function executionChildren(parentId) {
    return allAgents()
      .filter((agent) => agent.role === "execution" && agent.parent_id === parentId)
      .sort(compareExecutionAgents);
  }

  function selectedAgent() {
    return allAgents().find((agent) => agent.agent_id === state.selectedAgent) || null;
  }

  function latestAgentActivity(agent) {
    if (!agent) return 0;
    let latest = Math.max(dateValue(agent.updated_at), dateValue(agent.last_heartbeat_at), dateValue(agent.ended_at));
    for (let index = state.events.length - 1; index >= 0; index -= 1) {
      const event = state.events[index];
      if (event.agent_id === agent.agent_id) {
        latest = Math.max(latest, dateValue(event.created_at));
        break;
      }
    }
    return latest;
  }

  function agentMission(agent) {
    if (!agent) return "";
    if (agent.mission) return String(agent.mission);
    if (agent.role === "chief") return String(state.snapshot?.run?.prompt || agent.initial_prompt || "");
    return String(agent.initial_prompt || "");
  }

  function agentRoleLabel(agent) {
    if (agent?.kind === "bootstrap") return "Bootstrap";
    if (agent?.kind === "exploration") return "探索";
    return ROLE_NAMES[agent?.role] || agent?.role || "Agent";
  }

  function displayName(agent) {
    if (!agent) return "未选择 Agent";
    if (agent.role === "chief") return "首席 Agent";
    if (agent.role === "challenge") return agent.unique_code || "挑战 Agent";
    if (agent.kind === "bootstrap") return "Bootstrap";
    if (agent.kind === "exploration") return "探索";
    return executionAgentName(agent);
  }

  function preserveSelection() {
    const agents = allAgents();
    if (!agents.length) {
      state.selectedAgent = null;
      return;
    }
    if (state.selectedAgent && agents.some((agent) => agent.agent_id === state.selectedAgent)) return;
    const challenge = challengeAgents()[0];
    const fallback = challenge || chiefAgent() || agents[0];
    state.selectedAgent = fallback?.agent_id || null;
    if (fallback?.role === "challenge") state.expandedChallengeAgents.add(fallback.agent_id);
    state.pendingScrollRestore = true;
  }

  function mergeSnapshot(data) {
    const initial = !state.snapshot;
    const oldCursor = state.afterSequence;
    const incoming = Array.isArray(data.events) ? data.events : [];
    state.events = oldCursor === 0 ? incoming : mergeEvents(state.events, incoming).slice(-5000);
    state.afterSequence = Math.max(oldCursor, Number(data.event_cursor || 0));
    state.snapshot = { ...data, events: state.events };
    preserveSelection();

    if (oldCursor > 0) {
      incoming
        .filter((event) => Number(event.sequence) > oldCursor && event.agent_id && CONVERSATION_EVENTS.has(event.event_type))
        .forEach((event) => {
          const shouldFollow = event.agent_id === state.selectedAgent && state.follow;
          if (shouldFollow) return;
          state.unreadByAgent.set(event.agent_id, (state.unreadByAgent.get(event.agent_id) || 0) + 1);
        });
    }
    const update = {
      initial,
      meaningful: initial || incoming.some((event) => event.event_type !== "agent_heartbeat"),
    };
    if (update.initial || update.meaningful) {
      uiLog("debug", "snapshot_merged", {
        initial,
        incomingEvents: incoming.length,
        eventCursor: state.afterSequence,
        agentCount: allAgents().length,
      });
    }
    return update;
  }

  function saveSelectedScroll() {
    const stream = $("#conversation-stream");
    if (!stream || !state.selectedAgent) return;
    const atBottom = stream.scrollHeight - stream.scrollTop - stream.clientHeight <= 30;
    state.scrollByAgent.set(state.selectedAgent, { top: stream.scrollTop, atBottom });
  }

  function switchAgent(agentId) {
    const agent = allAgents().find((item) => item.agent_id === agentId);
    if (!agent || state.selectedAgent === agentId) {
      if (agent) mobilePane("conversation");
      uiLog("debug", "agent_switch_ignored", {
        agentId,
        reason: !agent ? "agent_not_found" : "already_selected",
      });
      return;
    }
    saveSelectedScroll();
    if (state.detailController) state.detailController.abort();
    state.loadingAgentId = null;
    state.requestToken += 1;
    state.selectedAgent = agentId;
    state.selectedDetail = null;
    state.detailBefore = 0;
    state.detailHasMore = false;
    state.pendingScrollRestore = true;
    state.unreadByAgent.delete(agentId);
    state.follow = state.scrollByAgent.get(agentId)?.atBottom ?? true;
    if (agent.role === "execution" && agent.parent_id) state.expandedChallengeAgents.add(agent.parent_id);
    uiLog("info", "agent_selected", {
      agentId,
      role: agent.role,
      uniqueCode: agent.unique_code || null,
      parentId: agent.parent_id || null,
    });
    renderAll();
    loadAgent(agentId, { reset: true });
    mobilePane("conversation");
  }

  async function loadAgent(agentId, { reset = false, older = false } = {}) {
    if (!agentId || (older && state.loadingOlder)) return;
    if (!older && state.loadingAgentId === agentId) return;
    if (older) state.loadingOlder = true;
    else state.loadingAgentId = agentId;
    if (!older && state.detailController) state.detailController.abort();
    const controller = new AbortController();
    if (!older) state.detailController = controller;
    const token = ++state.requestToken;
    const before = older ? state.detailBefore : 0;
    uiLog("debug", "agent_detail_request", {
      agentId,
      reset,
      older,
      beforeSequence: before || null,
      token,
    });
    try {
      const query = before ? `?before_sequence=${before}&limit=500` : "?limit=500";
      const response = await fetch(`/api/agents/${encodeURIComponent(agentId)}${query}`, {
        cache: "no-store",
        signal: controller.signal,
      });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const detail = await response.json();
      if (state.selectedAgent !== agentId) {
        uiLog("debug", "agent_detail_ignored", { agentId, reason: "selection_changed", token });
        return;
      }
      if (!older && token !== state.requestToken) {
        uiLog("debug", "agent_detail_ignored", { agentId, reason: "stale_request", token });
        return;
      }
      if (!reset && state.selectedDetail?.agent?.agent_id === agentId) {
        detail.events = mergeEvents(state.selectedDetail.events, detail.events);
      }
      state.selectedDetail = detail;
      if (reset || older) {
        state.detailBefore = Number(detail.next_before_sequence || 0);
        state.detailHasMore = Boolean(detail.has_more);
      }
      uiLog("debug", "agent_detail_loaded", {
        agentId,
        eventCount: Array.isArray(detail.events) ? detail.events.length : 0,
        hasMore: Boolean(detail.has_more),
        token,
      });
      renderAll();
    } catch (error) {
      if (error.name === "AbortError") {
        uiLog("debug", "agent_detail_aborted", { agentId, token });
        return;
      }
      if (state.selectedAgent !== agentId) {
        uiLog("debug", "agent_detail_error_ignored", { agentId, reason: "selection_changed", token });
        return;
      }
      uiLog("error", "agent_detail_failed", { agentId, message: error.message, token });
      state.selectedDetail = { error: error.message };
      renderDetails();
    } finally {
      if (older) state.loadingOlder = false;
      else if (state.loadingAgentId === agentId) state.loadingAgentId = null;
    }
  }

  async function poll() {
    try {
      const response = await fetch(`/api/snapshot?after_sequence=${state.afterSequence}`, { cache: "no-store" });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const update = mergeSnapshot(await response.json());
      if (update.meaningful) renderAll();
      else renderChrome();
      refreshRuntimeDuration();
      if (state.selectedAgent && !state.selectedDetail) loadAgent(state.selectedAgent, { reset: true });
    } catch (error) {
      setText("#monitor-status", "连接等待");
      setText("#captured-at", error.message);
      const now = Date.now();
      if (error.message !== lastPollError || now - lastPollErrorAt >= 5000) {
        uiLog("warn", "snapshot_poll_failed", { message: error.message, afterSequence: state.afterSequence });
        lastPollError = error.message;
        lastPollErrorAt = now;
      }
    } finally {
      refreshRuntimeDuration();
      window.setTimeout(poll, 750);
    }
  }

  function renderAll() {
    if (!state.snapshot) return;
    renderChrome();
    renderAgentTree();
    renderConversationHeader();
    renderConversation();
    renderDetails();
  }

  function renderChrome() {
    const run = state.snapshot.run || {};
    const monitor = state.snapshot.monitor || {};
    const latestResource = (state.snapshot.resources || []).at(-1) || {};
    setText("#run-id", `RUN ${short(run.run_id, 24)}`);
    setText("#run-status", statusLabel(run.status));
    setText("#run-phase", phaseLabel(run.phase));
    setText("#event-sequence", run.last_sequence || state.snapshot.latest_sequence || 0);
    setText(
      "#resource-readout",
      `${Number(latestResource.cpu_percent || 0).toFixed(0)}% / ${Number(latestResource.memory_percent || 0).toFixed(0)}%`,
    );
    setText("#monitor-status", monitor.mode === "frozen" ? `已冻结 · ${monitor.test_result || "结束"}` : "实时观测");
    setText("#captured-at", monitor.captured_at ? `更新 ${clock(monitor.captured_at)}` : "—");
    $("#run-status-dot").className = stateTone(run.status);
    setText("#mobile-agent-count", allAgents().length, "0");
  }

  function agentMatches(agent, query) {
    if (!query) return true;
    return [displayName(agent), agent.kind, agent.agent_id, agent.unique_code, agent.mission, agent.status]
      .filter(Boolean)
      .some((value) => String(value).toLowerCase().includes(query));
  }

  function renderAgentTree() {
    const target = $("#agent-tree");
    const query = $("#agent-search").value.trim().toLowerCase();
    const challenges = challengeAgents();
    const visibleGroups = [];
    for (const agent of challenges) {
      const children = executionChildren(agent.agent_id);
      const matchingChildren = children.filter((child) => agentMatches(child, query));
      if (query && !agentMatches(agent, query) && matchingChildren.length === 0) continue;
      visibleGroups.push(challengeAgentGroup(agent, children, matchingChildren, Boolean(query)));
    }
    target.replaceChildren(...visibleGroups);
    setText("#challenge-agent-count", challenges.length, "0");
    $("#agent-empty").classList.toggle("hidden", visibleGroups.length > 0);

    const chief = chiefAgent();
    const chiefButton = $("#chief-agent-button");
    chiefButton.disabled = !chief;
    chiefButton.classList.toggle("selected", Boolean(chief && state.selectedAgent === chief.agent_id));
    chiefButton.classList.toggle("completed", chief?.status === "completed");
    setText("#chief-agent-meta", chief ? `${statusLabel(chief.status)} · ${elapsed(latestAgentActivity(chief))}` : "等待创建");
    $(".chief-avatar").replaceChildren(makeAgentIcon("chief", agentIconStatus(chief)));
    const chiefUnread = chief ? state.unreadByAgent.get(chief.agent_id) || 0 : 0;
    chiefButton.setAttribute("aria-label", chiefUnread ? `切换到首席 Agent 视角，${chiefUnread} 条新消息` : "切换到首席 Agent 视角");
  }

  function challengeAgentGroup(agent, children, matchingChildren, searching) {
    const group = make("section", "challenge-agent-group");
    group.setAttribute("role", "treeitem");
    const selected = state.selectedAgent === agent.agent_id;
    const expanded = state.expandedChallengeAgents.has(agent.agent_id);
    const row = make("button", `challenge-agent-row ${selected ? "selected" : ""} ${agent.status === "completed" ? "completed" : ""}`);
    row.type = "button";
    row.setAttribute("aria-expanded", String(searching || expanded));
    const challenge = challengeForAgent(agent);
    row.setAttribute(
      "aria-label",
      `${agent.unique_code || "挑战 Agent"}，${challengeMachineLabel(challenge)}，Agent ${statusLabel(agent.status)}，${children.length} 个执行 Agent`,
    );
    const caret = make("span", `tree-caret ${searching || expanded ? "open" : ""}`, "›");
    const robot = make("span", "robot-slot");
    robot.append(makeAgentIcon("challenge", agentIconStatus(agent)));
    const copy = make("span", "agent-row-copy");
    const name = make("strong", "", agent.unique_code || "挑战 Agent");
    name.dataset.tooltip = agent.agent_id;
    copy.append(
      name,
      make("small", "", `${challengeMachineLabel(challenge)} · Agent ${statusLabel(agent.status)} · 创建 ${clock(agent.created_at)}`),
    );
    const count = make("span", "agent-child-count", children.length);
    row.append(caret, robot, copy, count);
    row.addEventListener("click", () => {
      const wasSelected = state.selectedAgent === agent.agent_id;
      const wasExpanded = state.expandedChallengeAgents.has(agent.agent_id);
      if (wasSelected) {
        const nextExpanded = !wasExpanded;
        if (nextExpanded) state.expandedChallengeAgents.add(agent.agent_id);
        else state.expandedChallengeAgents.delete(agent.agent_id);
        uiLog("info", "challenge_tree_toggle", {
          agentId: agent.agent_id,
          uniqueCode: agent.unique_code || null,
          expanded: nextExpanded,
          childCount: children.length,
        });
        renderAgentTree();
        return;
      }
      state.expandedChallengeAgents.add(agent.agent_id);
      uiLog("info", "challenge_tree_select", {
        agentId: agent.agent_id,
        uniqueCode: agent.unique_code || null,
        expanded: true,
        childCount: children.length,
      });
      switchAgent(agent.agent_id);
    });
    group.append(row);

    const list = make("div", `execution-agent-list ${expanded ? "open" : ""} ${searching ? "search-open" : ""}`);
    list.setAttribute("role", "group");
    const shownChildren = searching && !agentMatches(agent, $("#agent-search").value.trim().toLowerCase()) ? matchingChildren : children;
    shownChildren.forEach((child) => list.append(executionAgentRow(child)));
    if (!shownChildren.length && (expanded || searching)) list.append(make("p", "muted-line", "尚未创建执行 Agent"));
    group.append(list);
    return group;
  }

  function executionAgentRow(agent) {
    const selected = state.selectedAgent === agent.agent_id;
    const row = make("button", `execution-agent-row ${selected ? "selected" : ""} ${agent.status === "completed" ? "completed" : ""}`);
    row.type = "button";
    row.setAttribute("role", "treeitem");
    row.setAttribute("aria-label", `${displayName(agent)}，${statusLabel(agent.status)}，${agentStartLabel(agent)}`);
    const robot = make("span", "robot-slot");
    robot.append(makeAgentIcon("execution", agentIconStatus(agent)));
    const copy = make("span", "execution-copy");
    copy.append(make("strong", "", displayName(agent)), make("small", "", short(agent.mission || agent.agent_id, 34)));
    const unread = state.unreadByAgent.get(agent.agent_id) || 0;
    row.append(robot, copy);
    if (unread) {
      const tail = make("span", "execution-row-tail");
      tail.append(make("span", "agent-unread", unread > 99 ? "99+" : unread));
      row.append(tail);
    }
    row.addEventListener("click", () => switchAgent(agent.agent_id));
    return row;
  }

  function selectedEvents() {
    const agent = selectedAgent();
    if (!agent) return [];
    const globalEvents = state.events.filter((event) => event.agent_id === agent.agent_id);
    if (state.selectedDetail?.agent?.agent_id !== agent.agent_id) return globalEvents.slice(-120);
    const detailEvents = state.selectedDetail.events || [];
    const lastDetailSequence = Number(detailEvents.at(-1)?.sequence || 0);
    const liveEvents = globalEvents.filter((event) => Number(event.sequence) > lastDetailSequence);
    return mergeEvents(detailEvents, liveEvents);
  }

  function thinkingStatus(agent, events) {
    if (!agent) return { label: "等待选择", tone: "muted", spinning: false };
    if (agent.status === "queued" || agent.status === "pending") return { label: "排队中", tone: "warn", spinning: true };
    if (agent.status === "starting") return { label: "启动中", tone: "warn", spinning: true };
    if (TERMINAL.has(agent.status)) return { label: statusLabel(agent.status), tone: stateTone(agent.status), spinning: false };
    const latest = [...events].reverse().find((event) => event.event_type !== "agent_heartbeat");
    if (!latest) return { label: "思考中", tone: "good", spinning: true };
    if (latest.event_type === "tool_call") return { label: "调用工具", tone: "good", spinning: true };
    if (latest.event_type === "tool_result") return { label: "分析工具结果", tone: "good", spinning: true };
    if (latest.event_type === "assistant_response") return { label: latest.payload?.tool_names?.length ? "调用工具" : "生成结论", tone: "good", spinning: true };
    if (latest.event_type === "memory_updated" || latest.event_type === "context_compacted") return { label: "整理上下文", tone: "warn", spinning: true };
    if (latest.event_type === "agent_report") return { label: "生成报告", tone: "good", spinning: true };
    return { label: agent.status === "blocked" ? "等待处理" : "思考中", tone: agent.status === "blocked" ? "warn" : "good", spinning: true };
  }

  function renderConversationHeader() {
    const agent = selectedAgent();
    const events = selectedEvents();
    const thinking = thinkingStatus(agent, events);
    const avatar = $("#selected-avatar");
    avatar.replaceChildren(makeAgentIcon(agent?.role || "chief", agentIconStatus(agent)));
    setText("#selected-role", agent ? `${agentRoleLabel(agent)} · ${agent.unique_code || "全局"}` : "未选择 Agent");
    setText("#selected-name", agent ? displayName(agent) : "选择左侧 Agent");
    setText("#selected-mission", agent ? short(agentMission(agent) || agent.agent_id, 110) : "选择后显示该 Agent 的任务、思考和工具活动");
    $("#selected-mission").dataset.tooltip = agent ? agentMission(agent) || agent.agent_id : "";
    const live = $("#agent-live-state");
    live.className = `agent-live-state ${thinking.tone} ${thinking.spinning ? "spinning" : ""}`;
    setText("#agent-live-label", thinking.label);
  }

  function appendInline(target, text) {
    const source = String(text || "");
    const pattern = /(`[^`]+`|\*\*[^*]+\*\*)/g;
    let cursor = 0;
    let match;
    while ((match = pattern.exec(source))) {
      if (match.index > cursor) target.append(document.createTextNode(source.slice(cursor, match.index)));
      const token = match[0];
      if (token.startsWith("`")) target.append(make("code", "", token.slice(1, -1)));
      else target.append(make("strong", "", token.slice(2, -2)));
      cursor = match.index + token.length;
    }
    if (cursor < source.length) target.append(document.createTextNode(source.slice(cursor)));
  }

  function isBlockStart(line) {
    return /^```/.test(line) || /^#{1,6}\s+/.test(line) || /^\s*[-*]\s+/.test(line) || /^\s*\d+\.\s+/.test(line);
  }

  function renderStructuredText(target, value) {
    target.classList.add("structured-text");
    const lines = String(value || "").replace(/\r\n/g, "\n").split("\n");
    let index = 0;
    while (index < lines.length) {
      const line = lines[index];
      if (!line.trim()) {
        index += 1;
        continue;
      }
      const fence = line.match(/^```([^\s`]*)/);
      if (fence) {
        const codeLines = [];
        index += 1;
        while (index < lines.length && !/^```/.test(lines[index])) {
          codeLines.push(lines[index]);
          index += 1;
        }
        if (index < lines.length) index += 1;
        const pre = make("pre");
        const code = make("code", fence[1] ? `language-${fence[1]}` : "", codeLines.join("\n"));
        pre.append(code);
        target.append(pre);
        continue;
      }
      const heading = line.match(/^(#{1,6})\s+(.+)/);
      if (heading) {
        const level = Math.min(6, heading[1].length + 1);
        const element = make(`h${level}`);
        appendInline(element, heading[2]);
        target.append(element);
        index += 1;
        continue;
      }
      const unordered = line.match(/^\s*[-*]\s+(.+)/);
      const ordered = line.match(/^\s*\d+\.\s+(.+)/);
      if (unordered || ordered) {
        const list = make(ordered ? "ol" : "ul");
        const matcher = ordered ? /^\s*\d+\.\s+(.+)/ : /^\s*[-*]\s+(.+)/;
        while (index < lines.length) {
          const itemMatch = lines[index].match(matcher);
          if (!itemMatch) break;
          const item = make("li");
          appendInline(item, itemMatch[1]);
          list.append(item);
          index += 1;
        }
        target.append(list);
        continue;
      }
      const paragraphLines = [line];
      index += 1;
      while (index < lines.length && lines[index].trim() && !isBlockStart(lines[index])) {
        paragraphLines.push(lines[index]);
        index += 1;
      }
      const paragraph = make("p");
      appendInline(paragraph, paragraphLines.join("\n"));
      target.append(paragraph);
    }
  }

  function buildRawConversation(events) {
    const timeline = [];
    let toolEvents = [];
    const orderedEvents = [...(events || [])].sort((left, right) => Number(left.sequence) - Number(right.sequence));
    const flushToolGroup = () => {
      if (!toolEvents.length) return;
      timeline.push({
        kind: "tool_group",
        events: toolEvents,
        sequenceStart: Number(toolEvents[0].sequence || 0),
        sequenceEnd: Number(toolEvents.at(-1).sequence || 0),
      });
      toolEvents = [];
    };
    orderedEvents.forEach((event) => {
      const sequence = Number(event.sequence || 0);
      if (event.event_type === "tool_call" || event.event_type === "tool_result") {
        toolEvents.push(event);
        return;
      }
      if (event.event_type === "assistant_response") {
        const content = String(event.payload?.content || "").trim();
        if (content) {
          flushToolGroup();
          timeline.push({ kind: "answer", event, sequenceStart: sequence, sequenceEnd: sequence });
        }
        return;
      }
      if (event.event_type === "agent_report") {
        flushToolGroup();
        timeline.push({ kind: "report", event, sequenceStart: sequence, sequenceEnd: sequence });
      }
    });
    flushToolGroup();
    return timeline;
  }

  function buildConversationItems(events) {
    return buildRawConversation(events);
  }

  function renderConversation() {
    const stream = $("#conversation-stream");
    const previousTop = stream.scrollTop;
    const agent = selectedAgent();
    if (!agent) {
      stream.replaceChildren();
      $("#conversation-empty").classList.remove("hidden");
      $("#history-button").classList.add("hidden");
      return;
    }
    const column = make("div", "conversation-column conversation-timeline");
    const task = agentMission(agent);
    if (task) column.append(renderTaskMessage(agent, task));
    const events = selectedEvents();
    const items = buildConversationItems(events);
    items.forEach((item) => {
      if (item.kind === "answer") column.append(renderAnswer(item));
      else if (item.kind === "tool_group") column.append(renderToolGroup(item.events, item.sequenceStart, item.sequenceEnd));
      else if (item.kind === "report") column.append(renderReportTurn(item.event));
    });
    stream.replaceChildren(column);
    restoreToolScrollPositions(stream);
    $("#conversation-empty").classList.toggle("hidden", Boolean(task || items.length));
    $("#history-button").classList.toggle("hidden", !state.detailHasMore || !state.selectedAgent);
    $("#history-button").textContent = state.loadingOlder ? "正在加载…" : "加载更早记录";

    if (state.pendingScrollRestore) {
      const saved = state.scrollByAgent.get(agent.agent_id);
      if (saved && !saved.atBottom) stream.scrollTop = saved.top;
      else stream.scrollTop = stream.scrollHeight;
      state.pendingScrollRestore = false;
    } else if (state.follow) {
      stream.scrollTop = stream.scrollHeight;
      state.unreadByAgent.delete(agent.agent_id);
    } else {
      stream.scrollTop = previousTop;
    }
    renderNewMessagesButton();
  }

  function renderTaskMessage(agent, task) {
    const row = make("div", "task-message-row");
    const bubble = make("div", "task-message");
    const header = make("div", "task-message-header");
    header.append(
      make("span", "task-message-label", agent.role === "chief" ? "RUN 任务" : "AGENT 任务"),
      makeCopyButton("复制任务", task),
    );
    const content = make("div");
    renderStructuredText(content, task);
    bubble.append(header, content);
    row.append(bubble);
    return row;
  }

  function setTimelineRange(element, sequenceStart, sequenceEnd = sequenceStart) {
    element.dataset.sequenceStart = String(sequenceStart || 0);
    element.dataset.sequenceEnd = String(sequenceEnd || sequenceStart || 0);
    return element;
  }

  function renderAnswer(item) {
    const event = item.event;
    const turn = setTimelineRange(make("article", "assistant-turn timeline-node"), item.sequenceStart || event.sequence, item.sequenceEnd || event.sequence);
    const body = make("div", "assistant-message");
    const content = make("div");
    renderStructuredText(content, event.payload?.content || "");
    const footer = make("div", "message-footer");
    footer.append(make("time", "", clock(event.created_at)), makeCopyButton("复制消息", event.payload?.content || ""));
    body.append(content, footer);
    turn.append(body);
    return turn;
  }

  function toolRows(events) {
    const rows = [];
    const pending = new Map();
    events.forEach((event) => {
      if (event.event_type === "tool_call") {
        const id = String(event.payload?.tool_call_id || `sequence-${event.sequence}`);
        const row = { id: `tool-${event.sequence}`, call: event, result: null };
        rows.push(row);
        pending.set(id, row);
        return;
      }
      if (event.event_type === "tool_result") {
        const id = String(event.payload?.tool_call_id || "");
        const row = id ? pending.get(id) : null;
        if (row) {
          row.result = event;
          pending.delete(id);
        } else {
          rows.push({ id: `result-${event.sequence}`, call: null, result: event });
        }
      }
    });
    return rows;
  }

  function toolFailed(resultEvent) {
    if (!resultEvent) return false;
    const payload = resultEvent.payload || {};
    const result = payload.result === undefined ? payload : payload.result;
    if (result?.ok === false || payload.ok === false) return true;
    if (result?.error || payload.error) return true;
    const status = String(result?.data?.status || result?.status || "").toLowerCase();
    return ["failed", "error", "cancelled", "interrupted"].includes(status);
  }

  function toolOutputCount(rows) {
    return rows.filter((row) => row.result).length;
  }

  function renderToolGroup(events, sequenceStart, sequenceEnd) {
    const rows = toolRows(events);
    if (!rows.length) return null;
    const groupId = `tool-group-${sequenceStart}-${sequenceEnd}`;
    const expanded = state.expandedToolGroups.has(groupId);
    const callCount = rows.filter((row) => row.call).length;
    const outputCount = toolOutputCount(rows);
    const failureCount = rows.filter((row) => toolFailed(row.result)).length;
    const pendingCount = rows.filter((row) => row.call && !row.result).length;
    const statusClass = failureCount ? "error" : pendingCount ? "pending" : "completed";
    const section = setTimelineRange(make("section", `tool-activity-group timeline-node ${expanded ? "expanded" : ""}`), sequenceStart, sequenceEnd);
    section.setAttribute("aria-label", `工具活动，${callCount} 次调用，${outputCount} 条输出`);
    const summary = make("button", "tool-activity-head");
    summary.type = "button";
    summary.setAttribute("aria-expanded", String(expanded));
    summary.setAttribute("aria-controls", `${groupId}-body`);
    summary.dataset.tooltip = expanded ? "收起工具活动" : "展开工具活动";
    const iconSlot = make("span", `tool-event-icon status-${statusClass}`);
    iconSlot.append(makeSecaiIcon("tool"));
    const main = make("span", "tool-activity-main");
    const summaryParts = ["工具活动", `${callCount} 次调用`, outputCount ? `${outputCount} 条输出` : ""];
    if (failureCount) summaryParts.push(`${failureCount} 次失败`);
    if (pendingCount) summaryParts.push(`${pendingCount} 项等待结果`);
    main.append(make("strong", "", summaryParts.filter(Boolean).join(" · ")));
    summary.append(iconSlot, main, make("span", "chevron", "⌄"));
    summary.addEventListener("click", () => {
      const nextExpanded = !section.classList.contains("expanded");
      if (nextExpanded) state.expandedToolGroups.add(groupId);
      else state.expandedToolGroups.delete(groupId);
      section.classList.toggle("expanded", nextExpanded);
      summary.setAttribute("aria-expanded", String(nextExpanded));
      summary.dataset.tooltip = nextExpanded ? "收起工具活动" : "展开工具活动";
      shell.classList.toggle("is-open", nextExpanded);
      shell.setAttribute("aria-hidden", String(!nextExpanded));
    });
    section.append(summary);

    const shell = make("div", `tool-activity-body-shell ${expanded ? "is-open" : ""}`);
    shell.id = `${groupId}-body`;
    shell.setAttribute("aria-hidden", String(!expanded));
    const body = make("div", "tool-activity-body");
    rows.forEach((row) => body.append(renderToolRow(row, groupId)));
    shell.append(body);
    section.append(shell);
    return section;
  }

  function toolName(row) {
    return row.call?.payload?.tool_name || row.result?.payload?.tool_name || "unknown_tool";
  }

  function toolDisplayName(name) {
    if (TOOL_LABELS[name]) return TOOL_LABELS[name];
    if (name.startsWith("mcp__")) return name.split("__").filter(Boolean).join(" · ");
    return name.replace(/_/g, " ");
  }

  function isRecord(value) {
    return Boolean(value && typeof value === "object" && !Array.isArray(value));
  }

  function isHttpTool(name) {
    return String(name || "").startsWith("system_http_");
  }

  function toolArguments(row) {
    const value = row.call?.payload?.arguments;
    return isRecord(value) ? value : {};
  }

  function toolResultValue(row) {
    if (!row.result) return null;
    const payload = row.result.payload || {};
    return payload.result === undefined ? payload : payload.result;
  }

  function summaryValue(value, length = 96) {
    if (value === undefined || value === null || value === "") return "—";
    if (typeof value === "string") return short(value.replace(/\s+/g, " ").trim(), length);
    if (typeof value === "number" || typeof value === "boolean") return String(value);
    if (Array.isArray(value)) return `${value.length} 项`;
    if (isRecord(value)) return `${Object.keys(value).length} 个字段`;
    return short(value, length);
  }

  function summaryItemsForTool(name, args) {
    const items = [];
    const seen = new Set();
    const add = (label, value, key = label) => {
      if (value === undefined || value === null || value === "") return;
      items.push([label, summaryValue(value)]);
      seen.add(key);
    };
    const request = isRecord(args.request) ? args.request : args;
    if (name === "system_shell") {
      add("命令", args.command, "command");
      add("超时", args.timeout, "timeout");
    } else if (["system_read_file", "system_write_file", "system_edit_file"].includes(name)) {
      add("文件", args.file_path || args.filePath || args.path, "file");
      if (name === "system_write_file") add("内容", args.content === undefined ? undefined : `${copyText(args.content).length} 字符`, "content");
      if (name === "system_edit_file") {
        add("旧文本", args.old_string === undefined ? undefined : `${copyText(args.old_string).length} 字符`, "old_string");
        add("新文本", args.new_string === undefined ? undefined : `${copyText(args.new_string).length} 字符`, "new_string");
      }
    } else if (name === "system_http_request" || name === "system_http_probe") {
      add("方法", request.method || (name === "system_http_probe" ? "批量" : "GET"), "method");
      add("目标", request.url, "url");
      if (name === "system_http_probe") add("请求模板", args.cases, "cases");
      if (request.query && Object.keys(request.query).length) add("Query", `${Object.keys(request.query).length} 个字段`, "query");
      if (request.headers && Object.keys(request.headers).length) add("Header", `${Object.keys(request.headers).length} 个字段`, "headers");
      if (request.cookies && Object.keys(request.cookies).length) add("Cookie", `${Object.keys(request.cookies).length} 个字段`, "cookies");
      if (request.body !== undefined) add("Body", `${copyText(request.body).length} 字符`, "body");
      add("等待", args.wait_seconds, "wait_seconds");
      add("并发", args.concurrency, "concurrency");
    } else if (name === "system_http_response") {
      add("交互", args.interaction_id, "interaction_id");
      add("请求", args.request_id, "request_id");
      add("范围", args.offset_bytes === undefined ? undefined : `${args.offset_bytes} + ${args.length_bytes || 0} 字节`, "range");
    } else if (isHttpTool(name)) {
      add("交互", args.interaction_id, "interaction_id");
      add("等待", args.wait_seconds, "wait_seconds");
      add("游标", args.cursor, "cursor");
      add("数量", args.limit, "limit");
    } else if (name.includes("agent")) {
      add("标识", args.unique_code || args.agent_id, "identity");
      add("任务", args.mission, "mission");
      add("状态", args.status, "status");
      add("阶段", args.phase, "phase");
    } else {
      const preferred = ["file_path", "path", "pattern", "query", "skill_id", "resource", "status", "phase", "summary", "wait_seconds", "max_reports", "limit", "task_id", "interaction_id"];
      preferred.forEach((key) => add(key, args[key], key));
    }
    Object.entries(args).forEach(([key, value]) => {
      if (seen.has(key) || items.length >= 5) return;
      add(key, value, key);
    });
    if (!items.length) items.push(["参数", Object.keys(args).length ? `${Object.keys(args).length} 项` : "无参数"]);
    return items;
  }

  function resultSummaryItems(name, value) {
    const items = [];
    const data = isRecord(value?.data) ? value.data : value;
    const add = (label, candidate) => {
      if (candidate === undefined || candidate === null || candidate === "") return;
      items.push([label, summaryValue(candidate)]);
    };
    if (isRecord(data)) {
      add("状态", data.status || data.outcome || (data.ok === false ? "失败" : data.ok === true ? "成功" : undefined));
      add("HTTP 状态", data.status_code);
      add("交互", data.interaction_id);
      add("请求", data.request_id);
      add("耗时", data.elapsed_ms === undefined ? undefined : `${data.elapsed_ms} ms`);
      add("大小", data.body_bytes === undefined ? data.bytes_returned : `${data.body_bytes} 字节`);
      add("结果数", Array.isArray(data.results) ? data.results.length : undefined);
      add("错误", data.error || data.error_code);
      if (!items.length) add("输出", data);
    } else {
      add("输出", data);
    }
    return items.length ? items : [["输出", "—"]];
  }

  function resultContentItems(name, value) {
    const items = [];
    const seen = new Set();
    const data = isRecord(value?.data) ? value.data : value;
    const add = (label, candidate, key = label) => {
      if (seen.has(key) || candidate === undefined || candidate === null || candidate === "") return;
      const text = copyText(candidate).trim();
      if (!text) return;
      if (items.some(([, existing]) => existing === text)) return;
      seen.add(key);
      items.push([label, text]);
    };

    if (!isRecord(data)) {
      add("输出", data);
      return items;
    }

    if (name === "system_shell") {
      add("标准输出", data.output, "stdout");
      add("错误输出", data.stderr || data.error_output, "stderr");
    } else if (name === "system_read_file") {
      add("文件内容", data.content, "content");
    } else if (name === "system_write_file" || name === "system_edit_file") {
      add("文件", data.file_path || data.path, "path");
      add("操作结果", data.message || data.type || data.status, "operation");
    }

    [
      ["内容", "content"],
      ["输出", "output"],
      ["标准输出", "stdout"],
      ["错误输出", "stderr"],
      ["响应正文", "body"],
      ["文本", "text"],
      ["消息", "message"],
      ["摘要", "summary"],
      ["标题", "title"],
      ["错误详情", "error"],
    ].forEach(([label, key]) => add(label, data[key], key));

    if (!items.length) add("结构化输出", data, "structured");
    return items.slice(0, 4);
  }

  function renderSummaryGrid(items) {
    const grid = make("dl", "tool-summary-grid");
    items.forEach(([label, value]) => {
      grid.append(make("dt", "", label), make("dd", "", value));
    });
    return grid;
  }

  function renderSummaryContent(items, keyPrefix) {
    if (!items.length) return null;
    const section = make("section", "tool-summary-content");
    const header = make("div", "tool-detail-section-header");
    header.append(make("strong", "", "具体输出"));
    section.append(header);
    items.forEach(([label, value], index) => {
      const block = make("div", "tool-summary-content-block");
      const blockHeader = make("div", "tool-summary-content-header");
      blockHeader.append(make("strong", "", label), makeCopyButton(`复制${label}`, value));
      const pre = make("pre", "tool-summary-content-pre", value);
      pre.dataset.scrollKey = `${keyPrefix}-content-${index}`;
      pre.addEventListener("scroll", () => state.toolScrollPositions.set(pre.dataset.scrollKey, pre.scrollTop));
      block.append(blockHeader, pre);
      section.append(block);
    });
    return section;
  }

  function toolRecovery(value) {
    if (!isRecord(value)) return null;
    const error = isRecord(value.error) ? value.error : null;
    if (!error) return null;
    const retry = isRecord(error.retry) ? error.retry : {};
    const recovery = [
      error.stage ? `阶段：${error.stage}` : "",
      error.code ? `错误码：${error.code}` : "",
      retry.action && retry.action !== "none" ? `恢复动作：${retry.action}` : "",
      retry.tool ? `所需工具：${retry.tool}` : "",
    ].filter(Boolean).join(" · ");
    return recovery ? make("p", "muted-line tool-recovery", recovery) : null;
  }

  function toolTarget(row) {
    const argumentsValue = toolArguments(row);
    const request = isRecord(argumentsValue.request) ? argumentsValue.request : argumentsValue;
    if (typeof argumentsValue.description === "string" && argumentsValue.description.trim()) return short(argumentsValue.description.trim(), 56);
    const filePath = request.file_path || request.filePath || request.path;
    if (typeof filePath === "string" && filePath.trim()) return basename(filePath);
    if (typeof request.pattern === "string" && request.pattern.trim()) return short(request.pattern.trim(), 56);
    if (typeof argumentsValue.unique_code === "string" && argumentsValue.unique_code.trim()) return argumentsValue.unique_code.trim();
    if (typeof argumentsValue.mission === "string" && argumentsValue.mission.trim()) return short(argumentsValue.mission.trim(), 56);
    const url = request.url || request.address;
    if (typeof url === "string" && url.trim()) {
      try {
        return new URL(url).hostname || short(url, 56);
      } catch (_) {
        return short(url, 56);
      }
    }
    return "";
  }

  function toolIconKind(name) {
    if (name.includes("shell")) return "terminal";
    if (name.includes("read")) return "read";
    if (name.includes("write") || name.includes("edit")) return "edit";
    if (name.includes("grep") || name.includes("glob") || name.includes("list")) return "search";
    if (name.includes("create") && name.includes("agent")) return "agent";
    if (name.includes("report")) return "check";
    if (name.includes("task")) return "task";
    return "tool";
  }

  function renderToolRow(row, groupId) {
    const name = toolName(row);
    const failed = toolFailed(row.result);
    const pending = Boolean(row.call && !row.result);
    const status = failed ? "失败" : pending ? "等待结果" : row.call ? "完成" : "仅有输出";
    const statusClass = failed ? "error" : pending ? "pending" : row.call ? "completed" : "muted";
    const sequence = Number(row.call?.sequence || row.result?.sequence || 0);
    const callId = `${groupId}-${row.id}`;
    const expanded = state.expandedToolCalls.has(callId);
    const wrapper = setTimelineRange(make("section", "tool-row tool-event-card"), sequence, sequence);
    wrapper.setAttribute("aria-label", `${toolDisplayName(name)}，${status}`);
    const head = make("button", "tool-row-head tool-event-head");
    head.type = "button";
    head.setAttribute("aria-expanded", String(expanded));
    head.setAttribute("aria-controls", `${callId}-detail`);
    head.dataset.tooltip = expanded ? "收起调用详情" : "展开调用详情";
    const title = make("span", "tool-title tool-event-main");
    const target = toolTarget(row);
    title.append(make("strong", "", target ? `${toolDisplayName(name)}：${target}` : toolDisplayName(name)), make("small", "", name));
    const toolIcon = make("span", `tool-icon tool-event-icon status-${statusClass}`);
    toolIcon.append(makeSecaiIcon(toolIconKind(name)));
    head.append(
      toolIcon,
      title,
      make("span", `tool-state ${failed ? "bad" : pending ? "warn" : "good"}`, status),
      make("span", "chevron", "⌄"),
    );
    head.addEventListener("click", () => {
      const nextExpanded = head.getAttribute("aria-expanded") !== "true";
      if (nextExpanded) state.expandedToolCalls.add(callId);
      else state.expandedToolCalls.delete(callId);
      head.setAttribute("aria-expanded", String(nextExpanded));
      head.dataset.tooltip = nextExpanded ? "收起调用详情" : "展开调用详情";
      shell.classList.toggle("is-open", nextExpanded);
      shell.setAttribute("aria-hidden", String(!nextExpanded));
    });
    const shell = make("div", `tool-row-detail-shell ${expanded ? "is-open" : ""}`);
    shell.id = `${callId}-detail`;
    shell.setAttribute("aria-hidden", String(!expanded));
    const detail = make("div", "tool-detail tool-event-body");
    detail.append(renderToolViews(row, callId));
    shell.append(detail);
    wrapper.append(head, shell);
    return wrapper;
  }

  function renderToolViews(row, callId) {
    const name = toolName(row);
    const options = isHttpTool(name)
      ? [["packet", "报文"], ["json", "JSON"]]
      : [["summary", "摘要"], ["json", "JSON"]];
    let mode = state.toolViewModes.get(callId) || options[0][0];
    if (!options.some(([key]) => key === mode)) mode = options[0][0];
    state.toolViewModes.set(callId, mode);
    const wrapper = make("div", "tool-view");
    const tabs = make("div", "tool-view-tabs");
    tabs.setAttribute("role", "tablist");
    tabs.setAttribute("aria-label", `${toolDisplayName(name)}详情视图`);
    const panel = make("div", "tool-view-panel");
    panel.id = `${callId}-view`;
    const buttons = [];
    const update = (nextMode, focus = false) => {
      state.toolViewModes.set(callId, nextMode);
      buttons.forEach((button) => {
        const active = button.dataset.view === nextMode;
        button.classList.toggle("active", active);
        button.setAttribute("aria-selected", String(active));
        button.tabIndex = active ? 0 : -1;
      });
      panel.replaceChildren(renderToolView(row, callId, nextMode));
      restoreToolScrollPositions(panel);
      if (focus) buttons.find((button) => button.dataset.view === nextMode)?.focus();
    };
    options.forEach(([key, label]) => {
      const button = make("button", `tool-view-tab ${key === mode ? "active" : ""}`, label);
      button.type = "button";
      button.dataset.view = key;
      button.setAttribute("role", "tab");
      button.setAttribute("aria-selected", String(key === mode));
      button.setAttribute("aria-controls", panel.id);
      button.tabIndex = key === mode ? 0 : -1;
      button.addEventListener("click", () => update(key));
      tabs.append(button);
      buttons.push(button);
    });
    tabs.addEventListener("keydown", (event) => {
      if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) return;
      event.preventDefault();
      const index = buttons.indexOf(document.activeElement);
      const nextIndex = event.key === "Home" ? 0
        : event.key === "End" ? buttons.length - 1
          : (index + (event.key === "ArrowRight" ? 1 : -1) + buttons.length) % buttons.length;
      update(buttons[nextIndex].dataset.view, true);
    });
    wrapper.append(tabs, panel);
    update(mode);
    return wrapper;
  }

  function renderToolView(row, callId, mode) {
    if (mode === "json") return renderToolJsonView(row);
    if (mode === "packet") return renderHttpView(row, callId);
    return renderToolSummaryView(row);
  }

  function renderToolSummaryView(row) {
    const name = toolName(row);
    const args = toolArguments(row);
    const view = make("div", "tool-summary-view");
    view.append(toolSummarySection("参数摘要", summaryItemsForTool(name, args), "复制完整调用参数", args, "input"));
    if (row.result) {
      const result = toolResultValue(row);
      const recovery = toolRecovery(result);
      if (recovery) view.append(recovery);
      view.append(toolSummarySection("输出摘要", resultSummaryItems(name, result), "复制完整输出结果", result, "output"));
      const outputContent = renderSummaryContent(resultContentItems(name, result), row.id);
      if (outputContent) view.append(outputContent);
      const resultRef = result?.result_ref || row.result.payload?.result_ref;
      if (resultRef) view.append(make("p", "muted-line", `完整结果：${resultRef}`));
    } else {
      view.append(make("p", "muted-line", "工具尚未返回结果。"));
    }
    return view;
  }

  function toolSummarySection(label, items, copyLabel, copyValue, key) {
    const section = make("section", "tool-summary-section");
    const header = make("div", "tool-detail-section-header");
    const meta = make("span", "tool-detail-meta");
    meta.append(makeCopyButton(copyLabel, copyValue));
    header.append(make("strong", "", label), meta);
    section.append(header, renderSummaryGrid(items));
    section.dataset.summaryKey = key;
    return section;
  }

  function renderToolJsonView(row) {
    const view = make("div", "tool-json-view");
    if (row.call) view.append(toolDetailSection("调用参数", toolArguments(row), `${row.id}-input`));
    if (row.result) {
      const result = toolResultValue(row);
      const recovery = toolRecovery(result);
      if (recovery) view.append(recovery);
      view.append(toolDetailSection("输出结果", result, `${row.id}-output`));
    }
    if (!row.result) view.append(make("p", "muted-line", "工具尚未返回结果。"));
    return view;
  }

  function httpRequestEntries(name, args) {
    if (name === "system_http_probe") {
      return (Array.isArray(args.cases) ? args.cases : []).map((entry, index) => ({
        id: `request-${index + 1}`,
        kind: "request",
        index,
        request: isRecord(entry?.request) ? entry.request : entry,
        variables: entry?.variables,
        combine: entry?.combine,
      }));
    }
    if (name === "system_http_request") {
      const request = isRecord(args.request) ? args.request : args;
      return [
        {
          id: "request-1",
          kind: "request",
          index: 0,
          request: isRecord(request) ? request : {},
        },
      ];
    }
    return [];
  }

  function httpResultEntries(value) {
    const preview = httpPreviewValue(value);
    const data = isRecord(preview.value?.data) ? preview.value.data : preview.value;
    if (!isRecord(data)) return [];
    const list = Array.isArray(data.results) ? data.results
      : Array.isArray(data.preview) ? data.preview
        : Array.isArray(data.request_catalog) ? data.request_catalog : null;
    if (list) {
      return list.map((entry, index) => ({
        id: String(entry?.request_id || entry?.interaction_id || entry?.id || `response-${index + 1}`),
        kind: "response",
        index,
        response: isRecord(entry) ? entry : { content: entry },
        previewed: preview.previewed,
        previewFragment: preview.previewFragment,
      }));
    }
    const hasResponse = ["status_code", "final_url", "headers", "content", "bytes_returned", "body_bytes", "outcome"].some((key) => data[key] !== undefined);
    return hasResponse ? [{ id: String(data.request_id || "response-1"), kind: "response", index: 0, response: data, previewed: preview.previewed, previewFragment: preview.previewFragment }] : [];
  }

  function httpTargetContext(args) {
    const interactionId = args?.interaction_id;
    const requestId = args?.request_id;
    if (!interactionId && !requestId) return null;
    const events = [...(state.events || [])].reverse();
    for (const event of events) {
      if (event.event_type !== "tool_call") continue;
      const payload = event.payload || {};
      if (!isHttpTool(payload.tool_name) || !["system_http_request", "system_http_probe"].includes(payload.tool_name)) continue;
      const callArgs = isRecord(payload.arguments) ? payload.arguments : {};
      const callId = payload.tool_call_id;
      const resultEvent = events.find((candidate) => candidate.event_type === "tool_result" && candidate.payload?.tool_call_id === callId);
      const resultPayload = resultEvent?.payload || {};
      const result = resultPayload.result === undefined ? resultPayload : resultPayload.result;
      const preview = httpPreviewValue(result);
      const data = isRecord(preview.value?.data) ? preview.value.data : preview.value;
      const matchesInteraction = interactionId && data?.interaction_id === interactionId;
      const matchingResponse = Array.isArray(data?.results)
        ? data.results.find((entry) => requestId && entry?.request_id === requestId)
        : null;
      if (!matchesInteraction && !matchingResponse) continue;
      const requests = httpRequestEntries(payload.tool_name, callArgs);
      return { request: requests[0]?.request || null };
    }
    return null;
  }

  function normalizeJsonControls(source) {
    let output = "";
    let insideString = false;
    let escaped = false;
    for (const character of String(source || "")) {
      if (insideString && character === "\\" && !escaped) {
        output += character;
        escaped = true;
        continue;
      }
      if (character === '"' && !escaped) insideString = !insideString;
      if (insideString && character.charCodeAt(0) < 32) {
        output += character === "\n" ? "\\n" : character === "\r" ? "\\r" : character === "\t" ? "\\t" : " ";
      } else {
        output += character;
      }
      escaped = false;
    }
    return output;
  }

  function parseJsonFragment(source) {
    for (const candidate of [source, normalizeJsonControls(source)]) {
      try {
        return JSON.parse(candidate);
      } catch (_) {
        // A tool preview can end in the middle of a large string or object.
      }
    }
    return null;
  }

  function extractJsonArrayObjects(source, key) {
    const marker = `"${key}"`;
    const markerIndex = String(source || "").indexOf(marker);
    if (markerIndex < 0) return [];
    const openIndex = String(source).indexOf("[", markerIndex + marker.length);
    if (openIndex < 0) return [];
    const objects = [];
    let depth = 0;
    let start = -1;
    let insideString = false;
    let escaped = false;
    for (let index = openIndex + 1; index < source.length; index += 1) {
      const character = source[index];
      if (insideString) {
        if (character === "\\" && !escaped) {
          escaped = true;
          continue;
        }
        if (character === '"' && !escaped) insideString = false;
        escaped = false;
        continue;
      }
      if (character === '"') {
        insideString = true;
        continue;
      }
      if (character === "{") {
        if (depth === 0) start = index;
        depth += 1;
        continue;
      }
      if (character === "}") {
        depth -= 1;
        if (depth === 0 && start >= 0) {
          const parsed = parseJsonFragment(source.slice(start, index + 1));
          if (isRecord(parsed)) objects.push(parsed);
          start = -1;
        }
      }
      if (character === "]" && depth === 0) break;
    }
    return objects;
  }

  function httpPreviewValue(value) {
    if (!isRecord(value) || value.truncated !== true || typeof value.preview !== "string") {
      return { value, previewed: false };
    }
    const parsed = parseJsonFragment(value.preview);
    if (parsed) return { value: parsed, previewed: true };
    for (const key of ["results", "preview", "request_catalog"]) {
      const entries = extractJsonArrayObjects(value.preview, key);
      if (entries.length) return { value: { data: { [key]: entries } }, previewed: true, previewFragment: true };
    }
    return {
      value: {
        data: {
          content: value.preview,
          encoding: "json-preview",
        },
      },
      previewed: true,
      previewFragment: true,
    };
  }

  function httpTarget(value) {
    const target = value?.final_url || value?.url || value?.path || "";
    if (!target) return "未命名请求";
    try {
      const url = new URL(target);
      return `${url.hostname}${url.pathname || "/"}`;
    } catch (_) {
      return short(target, 80);
    }
  }

  function httpEntryLabel(entry, index) {
    const value = entry.kind === "request" ? entry.request : entry.response;
    const method = entry.kind === "request" ? String(value?.method || "GET").toUpperCase() : String(value?.status_code || value?.outcome || "响应");
    const size = value?.body_bytes === undefined ? value?.bytes_returned : value.body_bytes;
    const suffix = size === undefined ? "" : ` · ${size} B`;
    return `${index + 1}. ${method} · ${httpTarget(value)}${suffix}`;
  }

  function httpMetaItems(name, args, result) {
    const items = [];
    const add = (label, value) => {
      if (value !== undefined && value !== null && value !== "") items.push([label, summaryValue(value, 72)]);
    };
    const preview = httpPreviewValue(result);
    const data = isRecord(preview.value?.data) ? preview.value.data : preview.value;
    add("交互", args.interaction_id || data?.interaction_id);
    add("请求", args.request_id || data?.request_id);
    add("等待", args.wait_seconds);
    add("会话", args.session_id);
    add("并发", args.concurrency);
    add("范围", args.offset_bytes === undefined ? undefined : `${args.offset_bytes} + ${args.length_bytes || 0} 字节`);
    add("编码", data?.encoding);
    if (preview.previewed) add("载荷", "工具结果预览");
    if (preview.previewFragment) add("完整性", "结果列表可能不完整");
    if (data?.truncated === true || data?.eof === false) add("完整性", "当前仅为部分内容");
    return items;
  }

  function httpTargetItems(name, args, request, response, entry) {
    const items = [];
    const add = (label, value) => {
      if (value !== undefined && value !== null && value !== "") items.push([label, summaryValue(value, 120)]);
    };
    const url = request?.url || response?.final_url || response?.url || args.url;
    const parts = requestParts(url, request?.query);
    add("方法", request?.method);
    add("主机", parts.host);
    add("路径", parts.target);
    add("请求意图", request?.request_intent);
    if (isRecord(request?.query) && Object.keys(request.query).length) {
      add("查询参数", Object.entries(request.query).map(([key, value]) => `${key}=${summaryValue(value, 48)}`).join("&"));
    }
    if (entry?.variables && Object.keys(entry.variables).length) add("模板变量", Object.keys(entry.variables).join(", "));
    add("状态", response?.status_code === undefined ? response?.outcome : response.status_code);
    add("最终地址", response?.final_url);
    add("耗时", response?.elapsed_ms === undefined ? undefined : `${response.elapsed_ms} ms`);
    add("大小", response?.body_bytes === undefined ? response?.bytes_returned : `${response.body_bytes} 字节`);
    add("类型", response?.content_type);
    add("标题", response?.title);
    add("交互", args.interaction_id || response?.interaction_id);
    add("请求 ID", args.request_id || response?.request_id);
    return items;
  }

  function renderHttpTargetCard(name, args, request, response, entry) {
    const section = make("section", "http-target-card");
    const header = make("div", "tool-detail-section-header");
    const url = request?.url || response?.final_url || response?.url || args.url || "";
    header.append(make("strong", "", "目标信息"));
    if (url) header.append(makeCopyButton("复制目标 URL", url));
    section.append(header);
    section.append(make("div", `http-target-url ${url ? "" : "is-missing"}`, url || "目标 URL 未随此事件返回"));
    const items = httpTargetItems(name, args, request, response, entry);
    if (items.length) section.append(renderSummaryGrid(items));
    return section;
  }

  function renderHttpMeta(items) {
    if (!items.length) return null;
    const meta = make("div", "http-meta-line");
    items.forEach(([label, value]) => meta.append(make("span", "http-meta-item", `${label} ${value}`)));
    return meta;
  }

  function requestParts(url, query) {
    const original = String(url || "");
    try {
      const parsed = new URL(original);
      const params = new URLSearchParams(parsed.search);
      Object.entries(isRecord(query) ? query : {}).forEach(([key, value]) => {
        if (Array.isArray(value)) value.forEach((item) => params.append(key, String(item)));
        else params.set(key, String(value));
      });
      return { host: parsed.host, target: `${parsed.pathname || "/"}${params.toString() ? `?${params.toString()}` : ""}` };
    } catch (_) {
      return { host: "", target: original || "/" };
    }
  }

  function base64(value) {
    try {
      const bytes = new TextEncoder().encode(String(value));
      let binary = "";
      bytes.forEach((byte) => { binary += String.fromCharCode(byte); });
      return btoa(binary);
    } catch (_) {
      return String(value);
    }
  }

  function requestHeaderLines(request) {
    const headers = isRecord(request?.headers) ? Object.entries(request.headers).map(([key, value]) => [key, String(value)]) : [];
    const lower = new Set(headers.map(([key]) => key.toLowerCase()));
    const parts = requestParts(request?.url, request?.query);
    if (parts.host && !lower.has("host")) headers.unshift(["Host", parts.host]);
    if (isRecord(request?.cookies) && Object.keys(request.cookies).length && !lower.has("cookie")) {
      headers.push(["Cookie", Object.entries(request.cookies).map(([key, value]) => `${key}=${value}`).join("; ")]);
    }
    if (isRecord(request?.auth) && !lower.has("authorization")) {
      const auth = request.auth;
      if (auth.type === "bearer" && auth.token) headers.push(["Authorization", `Bearer ${auth.token}`]);
      if (auth.type === "basic" && auth.username !== undefined && auth.password !== undefined) headers.push(["Authorization", `Basic ${base64(`${auth.username}:${auth.password}`)}`]);
    }
    const body = request?.body;
    if (isRecord(body) && body.content_type && !lower.has("content-type")) headers.push(["Content-Type", body.content_type]);
    return headers;
  }

  function requestBodyText(body) {
    if (body === undefined || body === null) return "";
    if (!isRecord(body) || !body.type) return copyText(body);
    if (body.type === "json") return pretty(body.value);
    if (body.type === "form") return new URLSearchParams(Object.entries(body.value || {}).map(([key, value]) => [key, String(value)])).toString();
    if (body.type === "multipart") return pretty(body.value);
    return copyText(body.value);
  }

  function httpRequestText(request) {
    const parts = requestParts(request?.url, request?.query);
    const method = String(request?.method || "GET").toUpperCase();
    const lines = [`${method} ${parts.target} HTTP/1.1`];
    requestHeaderLines(request).forEach(([key, value]) => lines.push(`${key}: ${value}`));
    const body = requestBodyText(request?.body);
    if (body) lines.push("", body);
    return lines.join("\n");
  }

  function httpResponseText(response) {
    const lines = [];
    if (response?.status_code !== undefined) lines.push(`HTTP/1.1 ${response.status_code}`);
    const headers = isRecord(response?.headers) ? response.headers : isRecord(response?.header_features) ? response.header_features : {};
    Object.entries(headers).forEach(([key, value]) => lines.push(`${key}: ${value}`));
    const body = response?.content === undefined ? response?.body : response.content;
    if (body !== undefined && body !== null && body !== "") lines.push("", copyText(body));
    return lines.join("\n") || "当前事件没有可构造的 HTTP 响应报文。";
  }

  function renderHttpPacket(label, text, key, note) {
    const section = make("section", "http-packet-section");
    const header = make("div", "tool-detail-section-header");
    header.append(make("strong", "", label), makeCopyButton(`复制${label}`, text));
    section.append(header);
    if (note) section.append(make("p", "muted-line", note));
    const pre = make("pre", "http-packet-pre", text);
    pre.dataset.scrollKey = key;
    pre.addEventListener("scroll", () => state.toolScrollPositions.set(key, pre.scrollTop));
    section.append(pre);
    return section;
  }

  function renderHttpSelectionList(entries, callId, row) {
    if (entries.length <= 1) return null;
    const list = make("div", "http-selection-list");
    list.setAttribute("role", "listbox");
    list.setAttribute("aria-label", "HTTP 请求或响应列表");
    const selectedId = state.toolBatchSelections.get(callId) || entries[0].id;
    entries.forEach((entry, index) => {
      const button = make("button", `http-selection-item ${entry.id === selectedId ? "active" : ""}`);
      button.type = "button";
      button.setAttribute("role", "option");
      button.setAttribute("aria-selected", String(entry.id === selectedId));
      button.append(make("span", "http-selection-label", httpEntryLabel(entry, index)));
      button.addEventListener("click", () => {
        state.toolBatchSelections.set(callId, entry.id);
        const parent = button.closest(".tool-view-panel");
        if (parent) {
          parent.replaceChildren(renderHttpView(row, callId));
          restoreToolScrollPositions(parent);
        }
      });
      list.append(button);
    });
    return list;
  }

  function renderHttpView(row, callId) {
    const name = toolName(row);
    const args = toolArguments(row);
    const result = toolResultValue(row);
    const view = make("div", "http-view");
    const meta = renderHttpMeta(httpMetaItems(name, args, result));
    if (meta) view.append(meta);
    const requests = httpRequestEntries(name, args);
    const responses = row.result ? httpResultEntries(result) : [];
    const linkedRequest = httpTargetContext(args)?.request || null;
    const entries = responses.length > 1 ? responses : requests.length > 1 ? requests : [];
    if (entries.length > 1) {
      const selectedId = state.toolBatchSelections.get(callId) || entries[0].id;
      const list = renderHttpSelectionList(entries, callId, row);
      if (list) view.append(list);
      const selected = entries.find((entry) => entry.id === selectedId) || entries[0];
      view.append(renderHttpTargetCard(
        name,
        args,
        selected.kind === "request" ? selected.request : null,
        selected.kind === "response" ? selected.response : null,
        selected,
      ));
      if (selected.kind === "request") {
        view.append(renderHttpPacket("请求报文预览", httpRequestText(selected.request), `${callId}-${selected.id}-request`, "Host 等字段可能由目标 URL 推导；完整工具参数见 JSON 页签。"));
      } else {
        const partial = selected.response?.truncated === true || selected.response?.eof === false;
        const previewNote = selected.previewed ? (selected.previewFragment ? "工具结果是截断的 JSON 预览，当前显示预览原文；完整外层 JSON 见 JSON 页签。" : "当前报文由工具结果预览解析；完整外层 JSON 见 JSON 页签。") : "报文由当前工具结果重建，不代表字节级网络抓包。";
        view.append(renderHttpPacket("响应报文预览", httpResponseText(selected.response), `${callId}-${selected.id}-response`, partial ? "当前仅为部分内容，显示当前事件返回的字节范围。" : previewNote));
      }
      return view;
    }
    const request = requests[0]?.request || linkedRequest;
    const response = responses[0]?.response || null;
    if (request || response) view.append(renderHttpTargetCard(name, args, request, response, requests[0] || responses[0]));
    if (request) view.append(renderHttpPacket("请求报文预览", httpRequestText(request), `${callId}-request`, "Host 等字段可能由目标 URL 推导；完整工具参数见 JSON 页签。"));
    if (responses.length) {
      const partial = response?.truncated === true || response?.eof === false;
      const previewNote = responses[0].previewed ? (responses[0].previewFragment ? "工具结果是截断的 JSON 预览，当前显示预览原文；完整外层 JSON 见 JSON 页签。" : "当前报文由工具结果预览解析；完整外层 JSON 见 JSON 页签。") : "报文由当前工具结果重建，不代表字节级网络抓包。";
      view.append(renderHttpPacket("响应报文预览", httpResponseText(response), `${callId}-response`, partial ? "当前仅为部分内容，显示当前事件返回的字节范围。" : previewNote));
    }
    if (!requests.length && !responses.length) {
      view.append(make("p", "muted-line", row.result ? "当前 HTTP 操作返回的是交互状态，未包含可构造的请求或响应报文。" : "暂无可构造的 HTTP 报文。"));
    }
    const recovery = toolRecovery(result);
    if (recovery) view.append(recovery);
    return view;
  }

  function toolDetailSection(label, value, key) {
    const section = make("section", "tool-detail-section");
    const header = make("div", "tool-detail-section-header");
    const meta = make("span", "tool-detail-meta");
    meta.append(makeCopyButton(`复制${label}`, value));
    if (label === "输出结果") meta.append(make("span", "", `${copyText(value).length} 字符`));
    header.append(make("strong", "", label), meta);
    const pre = make("pre", "", pretty(value));
    pre.dataset.scrollKey = key;
    pre.addEventListener("scroll", () => state.toolScrollPositions.set(key, pre.scrollTop));
    section.append(header, pre);
    return section;
  }

  function restoreToolScrollPositions(container) {
    container.querySelectorAll("pre[data-scroll-key]").forEach((pre) => {
      const saved = state.toolScrollPositions.get(pre.dataset.scrollKey);
      if (saved !== undefined) pre.scrollTop = saved;
    });
  }

  function reportForEvent(event) {
    const reports = state.snapshot?.reports || [];
    const exact = reports.find((report) => report.agent_id === event.agent_id && Number(report.sequence) === Number(event.sequence));
    if (exact) return exact;
    const reportId = event.payload?.report_id;
    return reports.find((report) => report.report_id === reportId) || null;
  }

  function renderReportTurn(event) {
    const turn = setTimelineRange(make("article", "report-turn timeline-node"), event.sequence, event.sequence);
    const card = make("div", "report-message");
    const report = reportForEvent(event);
    const payload = report?.payload || state.selectedDetail?.agent?.final_report || {};
    const summary = payload.summary || payload.message || "Agent 已提交报告。";
    const header = make("div", "report-kicker");
    const meta = make("span", "report-kicker-meta");
    meta.append(
      make("time", "", clock(report?.created_at || event.created_at)),
      makeCopyButton("复制最终报告", summary),
    );
    header.append(make("span", "", "已提交报告"), meta);
    const content = make("div");
    renderStructuredText(content, summary);
    card.append(header, content);
    turn.append(card);
    return turn;
  }

  function renderNewMessagesButton() {
    const button = $("#new-messages-button");
    const unread = state.selectedAgent ? state.unreadByAgent.get(state.selectedAgent) || 0 : 0;
    button.classList.toggle("hidden", state.follow || unread === 0);
    button.textContent = unread ? `${unread} 条新消息 · 回到最新` : "回到最新";
  }

  function renderDetails() {
    const target = $("#details-content");
    const agent = selectedAgent();
    const detailAgent = state.selectedDetail?.agent || agent;
    if (!detailAgent && state.detailTab !== "runtime") {
      setText("#details-title", "Agent 详情");
      setText("#details-status", "—");
      target.replaceChildren(make("div", "empty-state", "选择 Agent 查看运行上下文"));
      return;
    }
    setText("#details-title", state.detailTab === "runtime" ? "运行数据" : displayName(detailAgent));
    setText("#details-status", state.detailTab === "runtime" ? statusLabel(state.snapshot?.run?.status) : statusLabel(detailAgent?.status));
    $("#details-status").className = `status-pill ${stateTone(state.detailTab === "runtime" ? state.snapshot?.run?.status : detailAgent?.status)}`;
    target.replaceChildren();
    if (state.selectedDetail?.error && state.detailTab !== "runtime") {
      target.append(make("div", "empty-state", `详情加载失败：${state.selectedDetail.error}`));
    } else if (state.detailTab === "overview") renderOverview(target, detailAgent);
    else if (state.detailTab === "prompt") renderPrompt(target, detailAgent);
    else if (state.detailTab === "memory") renderMemory(target, detailAgent);
    else if (state.detailTab === "report") renderReports(target, detailAgent);
    else if (state.detailTab === "runtime") renderRuntime(target);
    target.scrollTop = state.detailTabScroll.get(state.detailTab) || 0;
  }

  function detailGrid(items) {
    const grid = make("div", "detail-grid");
    items.forEach(([label, value, tooltip]) => {
      const stat = make("div", "detail-stat");
      stat.append(make("small", "", label), make("b", "", value || "—"));
      if (label === "已运行时长") stat.dataset.runtimeDuration = "true";
      if (tooltip) stat.dataset.tooltip = tooltip;
      grid.append(stat);
    });
    return grid;
  }

  function refreshRuntimeDuration() {
    const value = document.querySelector("[data-runtime-duration] b");
    if (!value || state.detailTab !== "overview") return;
    const agent = selectedAgent();
    const detailAgent = state.selectedDetail?.agent || agent;
    if (!detailAgent) return;
    const challenge = (state.snapshot?.challenges || []).find((item) => item.unique_code === detailAgent.unique_code);
    value.textContent = runtimeDuration(detailAgent, challenge);
  }

  function detailBlock(label, value) {
    const block = make("section", "detail-block");
    const header = make("div", "detail-block-header");
    header.append(make("p", "detail-label", label), makeCopyButton(`复制${label}`, value));
    block.append(header, make("pre", "detail-pre", pretty(value)));
    return block;
  }

  function renderOverview(target, agent) {
    const challenge = (state.snapshot.challenges || []).find((item) => item.unique_code === agent.unique_code);
    const identity = make("div", "identity-card");
    const identityAvatar = make("span", "robot-slot identity-avatar");
    identityAvatar.append(makeAgentIcon(agent.role, agentIconStatus(agent)));
    identity.append(identityAvatar);
    const copy = make("div", "identity-copy");
    copy.append(make("strong", "", agentRoleLabel(agent)), make("small", "", agent.agent_id));
    identity.append(copy);
    target.append(identity);
    if (agent.role === "chief") {
      const stats = chiefOverviewStats();
      target.append(detailGrid([
        ["提交 Flag", String(stats.submittedFlags)],
        ["获得分数", `${stats.score} 分`],
      ]));
    }
    const overviewStats = [
      ["状态", statusLabel(agent.status)],
      ["Challenge", agent.unique_code || "全局"],
      ["父 Agent", agent.parent_id ? short(agent.parent_id, 19) : "根 Agent", agent.parent_id || ""],
      ["Cycle", agent.cycle_id ? short(agent.cycle_id, 19) : "—", agent.cycle_id || ""],
      ["最近心跳", agent.last_heartbeat_at ? elapsed(agent.last_heartbeat_at) : "无"],
      ["创建时间", clock(agent.created_at)],
    ];
    if (agent.role === "chief" || agent.role === "challenge") {
      overviewStats.splice(1, 0, ["已运行时长", runtimeDuration(agent, challenge)]);
    }
    target.append(detailGrid(overviewStats));
    if (agent.mission) target.append(detailBlock("任务", agent.mission));
    if (challenge) {
      target.append(detailGrid([
        ["机器状态", challengeMachineLabel(challenge)],
        ["远端状态", challenge.container_status || "未知"],
        ["工作状态", statusLabel(challenge.work_status)],
        ["槽位", challenge.slot_occupied === true ? "已占用" : "已释放"],
      ]));
      const addressBlock = make("section", "detail-block");
      addressBlock.append(make("p", "detail-label", "目标地址"));
      const list = make("div", "address-list");
      (challenge.container_addr || []).forEach((address) => {
        const code = make("code", "address", address);
        code.dataset.tooltip = address;
        list.append(code);
      });
      if (!challenge.container_addr?.length) list.append(make("span", "muted-line", "未配置地址"));
      addressBlock.append(list);
      target.append(addressBlock, detailBlock("题目简介", challenge.description || "暂无简介"));
    }
    target.append(detailBlock("成功标准", pretty(agent.success_criteria || [])));
  }

  function renderPrompt(target, agent) {
    target.append(detailBlock("初始提示词", agent.initial_prompt || "—"));
    const effective = (state.selectedDetail?.events || []).find((event) => event.event_type === "test_effective_prompt");
    if (effective) target.append(detailBlock("测试有效提示词", effective.payload?.prompt || effective.payload?.content || pretty(effective.payload)));
    target.append(detailBlock("任务", agent.mission || "—"));
  }

  function renderMemory(target, agent) {
    target.append(
      detailBlock("会话记忆", agent.session_memory || "—"),
      detailBlock("上下文引用", pretty(agent.context_refs || [])),
      detailBlock("最近摘要序号", String(agent.last_summarized_sequence || 0)),
    );
  }

  function renderReports(target, agent) {
    target.append(detailBlock("最终报告", pretty(agent.final_report || {})));
    const reports = (state.snapshot.reports || []).filter((report) => report.agent_id === agent.agent_id).slice(-12).reverse();
    if (!reports.length) target.append(make("p", "muted-line", "暂无已提交报告。"));
    reports.forEach((report) => target.append(detailBlock(`REPORT #${report.sequence} · ${statusLabel(report.status)}`, pretty(report.payload))));
  }

  function runtimeStatGrid(items) {
    const grid = make("div", "runtime-summary-grid");
    items.forEach(([label, value]) => {
      const stat = make("div", "runtime-stat");
      stat.append(make("small", "", label), make("b", "", value));
      grid.append(stat);
    });
    return grid;
  }

  function renderRuntime(target) {
    const snapshot = state.snapshot;
    const agents = snapshot.agents || [];
    const activeAgents = agents.filter(isActive).length;
    const verifiedFindings = (snapshot.findings || []).filter((item) => item.verification_status === "verified").length;
    target.append(runtimeStatGrid([
      ["Agent", String(agents.length)],
      ["活跃", String(activeAgents)],
      ["报告", String((snapshot.reports || []).length)],
      ["已验证发现", String(verifiedFindings)],
    ]));
    target.append(resourceMeters(snapshot.resources || []));
    target.append(runtimeListCard("周期", snapshot.cycles || [], (item) => ({
      title: `${item.unique_code || "全局"} · Cycle ${item.cycle_number}`,
      meta: item.cycle_id,
      state: statusLabel(item.status),
      tone: stateTone(item.status),
    })));
    target.append(runtimeListCard("发现", snapshot.findings || [], (item) => ({
      title: item.summary || item.category,
      meta: `${item.unique_code || "全局"} · ${item.category}`,
      state: statusLabel(item.verification_status),
      tone: stateTone(item.verification_status),
    })));
    target.append(runtimeListCard("操作", snapshot.operations || [], (item) => ({
      title: item.operation_type,
      meta: `${item.unique_code || "全局"} · ${item.duration_ms ?? "—"} ms`,
      state: statusLabel(item.status),
      tone: stateTone(item.status),
    })));
    target.append(runtimeListCard("准入", snapshot.admissions || [], (item) => ({
      title: `${item.kind === "bootstrap" ? "Bootstrap" : item.kind === "exploration" ? "探索" : ROLE_NAMES[item.role] || item.role} · P${item.priority ?? "—"}`,
      meta: short(item.agent_id, 30),
      state: statusLabel(item.status),
      tone: stateTone(item.status),
    })));
    target.append(projectionCard(snapshot.projection || {}));
  }

  function resourceMeters(resources) {
    const latest = resources.at(-1) || {};
    const wrapper = make("div", "resource-readout-card");
    wrapper.append(resourceMeter("CPU", Number(latest.cpu_percent || 0), "cpu"), resourceMeter("MEM", Number(latest.memory_percent || 0), "memory"));
    return wrapper;
  }

  function resourceMeter(label, value, kind) {
    const meter = make("section", `resource-meter ${kind}`);
    const header = make("header");
    header.append(make("span", "", label), make("b", "", `${value.toFixed(0)}%`));
    const track = make("div", "meter-track");
    const fill = make("i");
    fill.style.setProperty("--meter-value", `${Math.min(100, Math.max(0, value))}%`);
    track.append(fill);
    meter.append(header, track);
    return meter;
  }

  function runtimeListCard(title, rows, presentation) {
    const card = make("section", "runtime-card");
    const header = make("div", "runtime-card-header");
    header.append(make("strong", "", title), make("span", "", rows.length));
    card.append(header);
    if (!rows.length) {
      card.append(make("p", "muted-line", "暂无数据"));
      return card;
    }
    const list = make("div", "runtime-list");
    rows.slice(-8).reverse().forEach((row) => {
      const item = presentation(row);
      const element = make("div", "runtime-row");
      const copy = make("div", "runtime-row-copy");
      const strong = make("strong", "", item.title || "—");
      strong.dataset.tooltip = item.title || "";
      copy.append(strong, make("small", "", item.meta || "—"));
      element.append(copy, make("span", `runtime-row-state ${item.tone || "muted"}`, item.state || "—"));
      list.append(element);
    });
    card.append(list);
    return card;
  }

  function projectionCard(projection) {
    const card = make("section", "runtime-card");
    const header = make("div", "runtime-card-header");
    header.append(make("strong", "", "状态投影"), make("span", "", projection.pending_count ? "待处理" : "同步"));
    card.append(header);
    [
      ["最后投影序号", projection.last_projected_sequence || 0],
      ["待投影事件", projection.pending_count || 0],
      ["最大重试次数", projection.max_attempts || 0],
      ["最近错误", projection.last_error || "无"],
    ].forEach(([label, value]) => {
      const line = make("div", "projection-line");
      line.append(make("span", "", label), make("b", "", short(value, 28)));
      card.append(line);
    });
    return card;
  }

  function mobilePane(name) {
    const previous = document.body.dataset.mobilePane || null;
    document.body.dataset.mobilePane = name;
    document.querySelectorAll("[data-mobile]").forEach((button) => button.classList.toggle("active", button.dataset.mobile === name));
    if (previous !== name) uiLog("debug", "mobile_pane_changed", { from: previous, to: name });
  }

  const RESIZE_LIMITS = {
    left: { min: 220, max: 420, property: "--left-width" },
    right: { min: 290, max: 480, property: "--right-width" },
  };
  let activeResize = null;

  function paneWidth(edge) {
    const property = RESIZE_LIMITS[edge].property;
    const value = Number.parseFloat(getComputedStyle(document.documentElement).getPropertyValue(property));
    return Number.isFinite(value) ? value : RESIZE_LIMITS[edge].min;
  }

  function paneWidthBounds(edge) {
    const limits = RESIZE_LIMITS[edge];
    const workbenchWidth = $(".workbench").getBoundingClientRect().width;
    const otherEdge = edge === "left" ? "right" : "left";
    const maxByCenter = workbenchWidth - paneWidth(otherEdge) - 520;
    return { min: limits.min, max: Math.max(limits.min, Math.min(limits.max, maxByCenter)) };
  }

  function setPaneWidth(edge, requested) {
    const limits = paneWidthBounds(edge);
    const width = Math.round(Math.min(limits.max, Math.max(limits.min, requested)));
    document.documentElement.style.setProperty(RESIZE_LIMITS[edge].property, `${width}px`);
    const handle = $(`.pane-resizer[data-resize="${edge}"]`);
    if (handle) {
      handle.setAttribute("aria-valuemin", String(limits.min));
      handle.setAttribute("aria-valuemax", String(limits.max));
      handle.setAttribute("aria-valuenow", String(width));
    }
  }

  function finishPaneResize() {
    if (!activeResize) return;
    uiLog("debug", "pane_resize_finished", {
      edge: activeResize.edge,
      width: paneWidth(activeResize.edge),
    });
    document.body.classList.remove("is-resizing");
    activeResize = null;
  }

  function setupPaneResizers() {
    document.querySelectorAll(".pane-resizer").forEach((handle) => {
      const edge = handle.dataset.resize;
      if (!RESIZE_LIMITS[edge]) return;
      setPaneWidth(edge, paneWidth(edge));
      handle.addEventListener("pointerdown", (event) => {
        if (window.innerWidth <= 1100) return;
        activeResize = { edge, pointerId: event.pointerId, startX: event.clientX, startWidth: paneWidth(edge) };
        uiLog("debug", "pane_resize_started", { edge, width: activeResize.startWidth });
        document.body.classList.add("is-resizing");
        handle.focus({ preventScroll: true });
        handle.setPointerCapture?.(event.pointerId);
        event.preventDefault();
      });
      handle.addEventListener("pointermove", (event) => {
        if (!activeResize || activeResize.pointerId !== event.pointerId) return;
        const delta = edge === "left" ? event.clientX - activeResize.startX : activeResize.startX - event.clientX;
        setPaneWidth(edge, activeResize.startWidth + delta);
      });
      handle.addEventListener("pointerup", finishPaneResize);
      handle.addEventListener("pointercancel", finishPaneResize);
      handle.addEventListener("lostpointercapture", finishPaneResize);
      handle.addEventListener("keydown", (event) => {
        const bounds = paneWidthBounds(edge);
        const current = paneWidth(edge);
        let next = current;
        if (event.key === "Home") next = bounds.min;
        else if (event.key === "End") next = bounds.max;
        else if (event.key === "ArrowLeft") next = current + (edge === "right" ? 1 : -1) * (event.shiftKey ? 32 : 8);
        else if (event.key === "ArrowRight") next = current + (edge === "left" ? 1 : -1) * (event.shiftKey ? 32 : 8);
        else return;
        event.preventDefault();
        setPaneWidth(edge, next);
      });
    });
  }

  function jumpToLatest() {
    const stream = $("#conversation-stream");
    state.follow = true;
    if (state.selectedAgent) state.unreadByAgent.delete(state.selectedAgent);
    stream.scrollTop = stream.scrollHeight;
    renderNewMessagesButton();
  }

  let tooltipTimer = null;
  let tooltipOwner = null;

  function hideTooltip() {
    if (tooltipTimer) window.clearTimeout(tooltipTimer);
    tooltipTimer = null;
    tooltipOwner = null;
    $("#tooltip-layer").hidden = true;
  }

  function showTooltip(owner, immediate = false) {
    const label = owner?.dataset?.tooltip;
    if (!label) return;
    if (tooltipTimer) window.clearTimeout(tooltipTimer);
    tooltipOwner = owner;
    tooltipTimer = window.setTimeout(() => {
      if (tooltipOwner !== owner || !owner.isConnected) return;
      const tooltip = $("#tooltip-layer");
      tooltip.textContent = label;
      tooltip.hidden = false;
      const ownerRect = owner.getBoundingClientRect();
      const tooltipRect = tooltip.getBoundingClientRect();
      let left = ownerRect.left + ownerRect.width / 2 - tooltipRect.width / 2;
      left = Math.max(8, Math.min(window.innerWidth - tooltipRect.width - 8, left));
      let top = ownerRect.bottom + 8;
      if (top + tooltipRect.height > window.innerHeight - 8) top = ownerRect.top - tooltipRect.height - 8;
      tooltip.style.left = `${Math.round(left)}px`;
      tooltip.style.top = `${Math.round(Math.max(8, top))}px`;
    }, immediate ? 0 : 320);
  }

  $("#chief-agent-button").addEventListener("click", () => {
    const chief = chiefAgent();
    if (chief) switchAgent(chief.agent_id);
  });

  $("#agent-search").addEventListener("input", renderAgentTree);
  $("#new-messages-button").addEventListener("click", jumpToLatest);
  $("#history-button").addEventListener("click", () => {
    if (state.selectedAgent && state.detailHasMore) loadAgent(state.selectedAgent, { older: true });
  });
  $("#conversation-stream").addEventListener("scroll", () => {
    const stream = $("#conversation-stream");
    const atBottom = stream.scrollHeight - stream.scrollTop - stream.clientHeight <= 30;
    state.follow = atBottom;
    if (state.selectedAgent) {
      state.scrollByAgent.set(state.selectedAgent, { top: stream.scrollTop, atBottom });
      if (atBottom) state.unreadByAgent.delete(state.selectedAgent);
    }
    renderNewMessagesButton();
  });
  $("#details-content").addEventListener("scroll", (event) => state.detailTabScroll.set(state.detailTab, event.currentTarget.scrollTop));
  document.querySelectorAll("[data-detail-tab]").forEach((button) => button.addEventListener("click", () => {
    state.detailTabScroll.set(state.detailTab, $("#details-content").scrollTop);
    state.detailTab = button.dataset.detailTab;
    document.querySelectorAll("[data-detail-tab]").forEach((item) => {
      const active = item === button;
      item.classList.toggle("active", active);
      item.setAttribute("aria-selected", String(active));
    });
    renderDetails();
  }));
  document.querySelectorAll("[data-mobile]").forEach((button) => button.addEventListener("click", () => mobilePane(button.dataset.mobile)));
  document.addEventListener("keydown", (event) => {
    if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "f") {
      event.preventDefault();
      mobilePane("agents");
      $("#agent-search").focus();
    }
    if (event.key === "Escape") hideTooltip();
  });
  document.addEventListener("pointerover", (event) => {
    const owner = event.target.closest?.("[data-tooltip]");
    if (owner) showTooltip(owner);
  });
  document.addEventListener("pointerout", (event) => {
    const owner = event.target.closest?.("[data-tooltip]");
    if (owner && !owner.contains(event.relatedTarget)) hideTooltip();
  });
  document.addEventListener("focusin", (event) => {
    const owner = event.target.closest?.("[data-tooltip]");
    if (owner) showTooltip(owner, true);
  });
  document.addEventListener("focusout", hideTooltip);
  document.addEventListener("scroll", hideTooltip, true);
  window.addEventListener("resize", () => {
    hideTooltip();
    if (window.innerWidth <= 1100) finishPaneResize();
  });

  window.addEventListener("error", (event) => {
    uiLog("error", "window_error", {
      message: event.message,
      source: event.filename || null,
      line: event.lineno || null,
      column: event.colno || null,
    });
  });
  window.addEventListener("unhandledrejection", (event) => {
    uiLog("error", "unhandled_rejection", {
      message: event.reason?.message || String(event.reason || "unknown rejection"),
    });
  });

  setupPaneResizers();
  uiLog("info", "workbench_ready", {
    viewport: `${window.innerWidth}x${window.innerHeight}`,
    mobilePane: document.body.dataset.mobilePane || null,
  });
  poll();
})();
