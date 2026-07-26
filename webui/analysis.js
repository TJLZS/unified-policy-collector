const loading = document.querySelector("#analysis-loading");
const errorPanel = document.querySelector("#analysis-error");
const errorMessage = document.querySelector("#analysis-error-message");
const content = document.querySelector("#analysis-content");
const issueList = document.querySelector("#issue-list");
const tableBody = document.querySelector("#module-table-body");
const tableEmpty = document.querySelector("#module-empty");
const searchInput = document.querySelector("#module-search");
const statusFilter = document.querySelector("#status-filter");
const reportDownload = document.querySelector("#report-download");

let report = null;

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function statusLabel(status) {
  return {
    success: "成功",
    partial: "部分完成",
    failed: "失败",
    not_applicable: "不适用",
    skipped: "跳过",
  }[status] || status || "未知";
}

function formatTime(value) {
  if (!value) return "—";
  try {
    return new Intl.DateTimeFormat("zh-CN", {
      dateStyle: "medium",
      timeStyle: "medium",
    }).format(new Date(value));
  } catch {
    return value;
  }
}

function statusMarkup(status) {
  return `<span class="status status-${escapeHtml(status)}">${escapeHtml(statusLabel(status))}</span>`;
}

function renderOverview() {
  const target = report.target || {};
  document.querySelector("#analysis-target").textContent =
    target.target_ip || "未知目标";
  document.querySelector("#analysis-meta").textContent = [
    target.target_type || "未知设备",
    target.security_device || null,
    formatTime(report.started_at),
    `端口 ${target.port ?? "—"}`,
  ]
    .filter(Boolean)
    .join(" · ");
  const collection = document.querySelector("#collection-status");
  collection.className = `status-text status-${report.collection_status}`;
  collection.textContent = statusLabel(report.collection_status);
  const assessment = document.querySelector("#assessment-status");
  assessment.className = `status-text status-${report.assessment_status}`;
  assessment.textContent = statusLabel(report.assessment_status);
  const counts = report.counts || {};
  ["success", "failed", "not_applicable", "skipped"].forEach((status) => {
    document.querySelector(`#count-${status.replace("_", "-")}`).textContent =
      Number(counts[status] || 0);
  });
}

function renderIssues() {
  const issues = (report.items || []).filter((item) => item.status === "failed");
  if (!issues.length) {
    issueList.innerHTML = `
      <div class="analysis-clear">
        <strong>没有需要处理的失败项</strong>
        <p>不适用和跳过项不会降低有效状态。</p>
      </div>
    `;
    return;
  }
  issueList.innerHTML = issues
    .map((item) => {
      const recommendations = (item.recommendations || [])
        .map((value) => `<li>${escapeHtml(value)}</li>`)
        .join("");
      const evidence = item.evidence_excerpt
        ? `<pre>${escapeHtml(item.evidence_excerpt)}</pre>`
        : '<p class="evidence-empty">暂无可安全展示的证据片段，请核对原始输出。</p>';
      return `
        <article class="issue-card">
          <div class="issue-heading">
            <div>
              ${statusMarkup(item.status)}
              <h3>${escapeHtml(item.name)}</h3>
            </div>
            <code>${escapeHtml(item.reason_code)}</code>
          </div>
          <p class="issue-reason">${escapeHtml(item.reason)}</p>
          <dl class="issue-meta">
            <div><dt>返回码</dt><dd>${escapeHtml(item.return_code ?? "—")}</dd></div>
            <div><dt>证据文件</dt><dd>${escapeHtml(item.evidence_file || "—")}</dd></div>
          </dl>
          <div class="evidence-block">
            <small>脱敏证据片段</small>
            ${evidence}
          </div>
          <div class="recommendations">
            <small>建议检查</small>
            <ol>${recommendations || "<li>查看原始输出并人工核查。</li>"}</ol>
          </div>
        </article>
      `;
    })
    .join("");
}

function renderModules() {
  const term = searchInput.value.trim().toLocaleLowerCase();
  const selectedStatus = statusFilter.value;
  const items = (report.items || []).filter((item) => {
    const matchesName = String(item.name || "")
      .toLocaleLowerCase()
      .includes(term);
    const matchesStatus =
      selectedStatus === "all" || item.status === selectedStatus;
    return matchesName && matchesStatus;
  });
  tableBody.innerHTML = items
    .map(
      (item) => `
        <tr>
          <td>${statusMarkup(item.status)}</td>
          <td><strong>${escapeHtml(item.name)}</strong></td>
          <td>${escapeHtml(item.reason)}</td>
          <td><code>${escapeHtml(item.return_code ?? "—")}</code></td>
          <td><code>${escapeHtml(item.evidence_file || "—")}</code></td>
        </tr>
      `,
    )
    .join("");
  tableEmpty.hidden = items.length > 0;
}

async function initialize() {
  const runId = decodeURIComponent(
    window.location.pathname.split("/").filter(Boolean).at(-1) || "",
  );
  reportDownload.href = `/api/runs/${encodeURIComponent(runId)}/report`;
  try {
    const response = await fetch(`/api/runs/${encodeURIComponent(runId)}`, {
      cache: "no-store",
    });
    if (!response.ok) {
      const payload = await response.json().catch(() => ({}));
      throw new Error(payload.detail || "采集记录不存在或无法分析。");
    }
    report = await response.json();
    renderOverview();
    renderIssues();
    renderModules();
    loading.hidden = true;
    content.hidden = false;
  } catch (error) {
    loading.hidden = true;
    errorMessage.textContent = error.message || "无法读取本地分析报告。";
    errorPanel.hidden = false;
  }
}

searchInput.addEventListener("input", renderModules);
statusFilter.addEventListener("change", renderModules);
initialize();
