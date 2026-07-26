const form = document.querySelector("#collector-form");
const jobsContainer = document.querySelector("#jobs");
const runsContainer = document.querySelector("#runs");
const formError = document.querySelector("#form-error");
const securitySelect = document.querySelector("#security-device");
const adapterHint = document.querySelector("#adapter-hint");
const portInput = document.querySelector("#port");
const passwordInput = document.querySelector("#password");
const sudoPasswordInput = document.querySelector("#sudo-password");
const useSudoInput = document.querySelector("#use-sudo");
const sudoPasswordField = document.querySelector("#sudo-password-field");
const httpsInput = document.querySelector("#winrm-https");
const insecureInput = document.querySelector("#winrm-insecure");
const defaultPaths = document.querySelector("#default-paths");
const customPathEditor = document.querySelector("#custom-path-editor");
const customPathsInput = document.querySelector("#custom-paths");
const editPathsButton = document.querySelector("#edit-paths");
const resetPathsButton = document.querySelector("#reset-paths");
const pathMode = document.querySelector("#path-mode");
const pathStatus = document.querySelector("#path-status");

let metadata = { security_devices: [] };
let activeJobs = [];
let pollTimer = null;
let pathsEditing = false;
let displayedAdapterKey = null;

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function targetType() {
  return form.elements.target_type.value;
}

function selectedAdapter() {
  return metadata.security_devices.find(
    (device) => device.key === securitySelect.value,
  );
}

function setPathEditing(editing) {
  pathsEditing = editing;
  defaultPaths.hidden = editing;
  customPathEditor.hidden = !editing;
  editPathsButton.hidden = editing;
  pathMode.textContent = editing ? "自定义" : "默认";
  pathMode.classList.toggle("path-mode-custom", editing);
  pathStatus.textContent = editing
    ? "将使用下面的自定义路径；每行可以填写一个文件或目录。"
    : "使用默认规则路径；不修改即可直接采集。";
  if (editing) {
    const adapter = selectedAdapter();
    if (adapter && !customPathsInput.value.trim()) {
      customPathsInput.value = adapter.paths.join("\n");
    }
    customPathsInput.required = true;
    customPathsInput.focus();
  } else {
    customPathsInput.required = false;
    customPathsInput.value = "";
  }
}

function updateAdapter() {
  const adapter = selectedAdapter();
  if (!adapter) return;
  const mode = adapter.docker ? "Docker 宿主机采集" : "SSH 文件采集";
  adapterHint.textContent = `${mode} · 默认检查 ${adapter.paths.length} 个规则路径`;
  document.querySelectorAll(".docker-only").forEach((element) => {
    element.hidden = !adapter.docker;
  });
  if (displayedAdapterKey !== adapter.key) {
    displayedAdapterKey = adapter.key;
    defaultPaths.innerHTML = adapter.paths
      .map((path) => `<code>${escapeHtml(path)}</code>`)
      .join("");
    setPathEditing(false);
  }
}

function updateTargetFields(resetPort = true) {
  const type = targetType();
  document.querySelectorAll(".security-only").forEach((element) => {
    element.hidden = type !== "security";
  });
  document.querySelectorAll(".windows-only").forEach((element) => {
    element.hidden = type !== "windows";
  });
  document.querySelectorAll(".ssh-only").forEach((element) => {
    element.hidden = type === "windows";
  });
  sudoPasswordField.hidden = type === "windows" || !useSudoInput.checked;
  if (type !== "security") {
    document.querySelectorAll(".docker-only").forEach((element) => {
      element.hidden = true;
    });
  } else {
    updateAdapter();
  }
  if (resetPort) {
    portInput.value =
      type === "windows" ? (httpsInput.checked ? "5986" : "5985") : "22";
  }
  insecureInput.disabled = type !== "windows" || !httpsInput.checked;
}

function statusLabel(status) {
  const labels = {
    pending: "等待",
    running: "执行中",
    success: "成功",
    partial: "部分完成",
    failed: "失败",
    not_applicable: "不适用",
    skipped: "跳过",
  };
  return labels[status] || status;
}

function formatTime(value) {
  if (!value) return "—";
  try {
    return new Intl.DateTimeFormat("zh-CN", {
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      month: "2-digit",
      day: "2-digit",
    }).format(new Date(value));
  } catch {
    return value;
  }
}

function jobResultMarkup(job) {
  if (!job.result) return "";
  if (job.action === "check") {
    const details = Object.entries(job.result)
      .map(([key, value]) => `${escapeHtml(key)}: ${escapeHtml(value)}`)
      .join("<br>");
    return `<div class="job-result">${details}</div>`;
  }
  const runDir = escapeHtml(job.result.run_dir || "—");
  const passed = (job.result.successful_modules || []).length;
  const failed = (job.result.failed_modules || []).length;
  return `
    <div class="job-result">
      成功项 ${passed} · 失败项 ${failed}<br>
      本地目录：<code>${runDir}</code>
    </div>
  `;
}

function renderJobs() {
  if (!activeJobs.length) {
    jobsContainer.innerHTML = `
      <div class="empty-state">
        <span class="radar" aria-hidden="true"></span>
        <h3>等待采集任务</h3>
        <p>建议先执行连接检查，确认端口、认证和目标能力。</p>
      </div>
    `;
    return;
  }
  jobsContainer.innerHTML = activeJobs
    .map((job) => {
      const type = escapeHtml(job.target.target_type);
      const host = escapeHtml(job.target.target_ip);
      return `
        <article class="job-card">
          <div class="job-top">
            <div class="job-target">
              <strong>${host}</strong>
              <small>${type} · ${job.action === "check" ? "连接检查" : "策略采集"}</small>
            </div>
            <span class="status status-${escapeHtml(job.status)}">${escapeHtml(statusLabel(job.status))}</span>
          </div>
          <p class="job-message">${escapeHtml(job.message)}</p>
          <div class="job-meta">
            <span>${escapeHtml(formatTime(job.created_at))}</span>
            <span>${escapeHtml(job.id.slice(0, 8))}</span>
          </div>
          ${jobResultMarkup(job)}
        </article>
      `;
    })
    .join("");
}

function renderRuns(runs) {
  if (!runs.length) {
    runsContainer.innerHTML = '<p class="history-empty">暂无本地采集记录。</p>';
    return;
  }
  runsContainer.innerHTML = runs
    .slice(0, 9)
    .map((run) => {
      const collectionStatus = run.collection_status || "failed";
      const assessmentStatus = run.assessment_status || "failed";
      const counts = run.counts || {};
      return `
        <article class="run-card">
          <div>
            <div class="run-statuses">
              <span>
                <small>原始</small>
                <b class="status status-${escapeHtml(collectionStatus)}">${escapeHtml(statusLabel(collectionStatus))}</b>
              </span>
              <span>
                <small>有效</small>
                <b class="status status-${escapeHtml(assessmentStatus)}">${escapeHtml(statusLabel(assessmentStatus))}</b>
              </span>
            </div>
            <h3>${escapeHtml(run.target_ip)}</h3>
            <p>${escapeHtml(run.target_type)} · ${escapeHtml(formatTime(run.started_at))}</p>
          </div>
          <div>
            <small>成功 ${Number(counts.success || 0)} · 失败 ${Number(counts.failed || 0)} · 不适用 ${Number(counts.not_applicable || 0)}</small>
            <a class="run-analysis-link" href="/runs/${encodeURIComponent(run.run_id)}">查看分析 →</a>
          </div>
        </article>
      `;
    })
    .join("");
}

async function loadJobs() {
  try {
    const response = await fetch("/api/jobs", { cache: "no-store" });
    if (!response.ok) return;
    activeJobs = await response.json();
    renderJobs();
    const isRunning = activeJobs.some((job) =>
      ["queued", "running"].includes(job.state),
    );
    if (!isRunning && pollTimer) {
      clearInterval(pollTimer);
      pollTimer = null;
      loadRuns();
    }
  } catch {
    // 下一次手动刷新或轮询会重试。
  }
}

async function loadRuns() {
  try {
    const response = await fetch("/api/runs", { cache: "no-store" });
    if (response.ok) renderRuns(await response.json());
  } catch {
    runsContainer.innerHTML =
      '<p class="history-empty">暂时无法读取本地结果。</p>';
  }
}

function startPolling() {
  if (pollTimer) return;
  pollTimer = setInterval(loadJobs, 1000);
}

function requestPayload(action) {
  const paths = customPathsInput.value
    .split(/\r?\n/)
    .map((value) => value.trim())
    .filter(Boolean);
  return {
    action,
    target_type: targetType(),
    host: form.elements.host.value.trim(),
    port: Number(portInput.value),
    username: form.elements.username.value.trim(),
    password: passwordInput.value,
    use_sudo: targetType() !== "windows" && useSudoInput.checked,
    sudo_password: sudoPasswordInput.value || null,
    security_device:
      targetType() === "security" ? securitySelect.value : null,
    custom_paths:
      targetType() === "security" && pathsEditing ? paths : [],
    container_name:
      targetType() === "security"
        ? form.elements.container_name.value.trim() || null
        : null,
    winrm_https: targetType() === "windows" && httpsInput.checked,
    winrm_insecure:
      targetType() === "windows" && form.elements.winrm_insecure.checked,
    trust_new_host_key:
      targetType() !== "windows" && form.elements.trust_new_host_key.checked,
  };
}

async function submitJob(action, submitter) {
  formError.textContent = "";
  const payload = requestPayload(action);
  document.querySelectorAll(".button").forEach((button) => {
    button.disabled = true;
  });
  submitter.querySelector("span").textContent =
    action === "check" ? "正在提交…" : "正在启动…";
  try {
    const response = await fetch("/api/jobs", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const result = await response.json();
    if (!response.ok) {
      throw new Error(
        typeof result.detail === "string" ? result.detail : "输入信息不完整",
      );
    }
    passwordInput.value = "";
    sudoPasswordInput.value = "";
    activeJobs.unshift(result);
    renderJobs();
    startPolling();
  } catch (error) {
    formError.textContent = error.message || "任务提交失败";
  } finally {
    document.querySelectorAll(".button").forEach((button) => {
      button.disabled = false;
    });
    submitter.querySelector("span").textContent =
      action === "check" ? "检查连接" : "开始采集";
  }
}

async function initialize() {
  try {
    const response = await fetch("/api/meta");
    metadata = await response.json();
    securitySelect.innerHTML = metadata.security_devices
      .map(
        (device) =>
          `<option value="${escapeHtml(device.key)}">${escapeHtml(device.name)}</option>`,
      )
      .join("");
    updateTargetFields(false);
  } catch {
    formError.textContent = "无法加载设备适配器，请刷新页面。";
  }
  await Promise.all([loadJobs(), loadRuns()]);
  if (activeJobs.some((job) => ["queued", "running"].includes(job.state))) {
    startPolling();
  }
}

form.addEventListener("change", (event) => {
  if (event.target.name === "target_type") updateTargetFields();
  if (event.target === securitySelect) updateAdapter();
  if (event.target === useSudoInput) {
    sudoPasswordField.hidden = !useSudoInput.checked;
  }
  if (event.target === httpsInput) {
    portInput.value = httpsInput.checked ? "5986" : "5985";
    insecureInput.disabled = !httpsInput.checked;
    if (!httpsInput.checked) insecureInput.checked = false;
  }
});

form.addEventListener("submit", (event) => {
  event.preventDefault();
  const submitter =
    event.submitter || form.querySelector('[data-action="collect"]');
  submitJob(submitter.dataset.action, submitter);
});

document.querySelectorAll(".reveal").forEach((button) => {
  button.addEventListener("click", () => {
    const input = document.querySelector(`#${button.dataset.reveal}`);
    const hidden = input.type === "password";
    input.type = hidden ? "text" : "password";
    button.textContent = hidden ? "隐藏" : "显示";
  });
});

document.querySelector("#refresh-jobs").addEventListener("click", loadJobs);
editPathsButton.addEventListener("click", () => setPathEditing(true));
resetPathsButton.addEventListener("click", () => setPathEditing(false));

initialize();
