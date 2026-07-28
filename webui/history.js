const filters = document.querySelector("#history-filters");
const typeInput = document.querySelector("#history-target-type");
const ipInput = document.querySelector("#history-target-ip");
const statusInput = document.querySelector("#history-status");
const pageSizeInput = document.querySelector("#history-page-size");
const totalElement = document.querySelector("#history-total");
const loading = document.querySelector("#history-loading");
const errorPanel = document.querySelector("#history-error");
const errorMessage = document.querySelector("#history-error-message");
const runsContainer = document.querySelector("#history-runs");
const emptyPanel = document.querySelector("#history-empty");
const pagination = document.querySelector("#history-pagination");
const pageLabel = document.querySelector("#history-page-label");
const previousButton = document.querySelector("#history-prev");
const nextButton = document.querySelector("#history-next");

let currentPage = 1;
let totalPages = 0;
let historyRequestGeneration = 0;

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
  }[status] || status || "未知";
}

function typeLabel(type) {
  return {
    linux: "Linux",
    windows: "Windows",
    security: "安全设备",
  }[type] || type || "未知类型";
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

function queryParameters(page) {
  const parameters = new URLSearchParams({
    page: String(page),
    page_size: pageSizeInput.value,
  });
  if (typeInput.value) parameters.set("target_type", typeInput.value);
  if (ipInput.value.trim()) parameters.set("target_ip", ipInput.value.trim());
  if (statusInput.value) parameters.set("status", statusInput.value);
  return parameters;
}

function syncUrl(parameters) {
  const visible = new URLSearchParams(parameters);
  if (visible.get("page") === "1") visible.delete("page");
  if (visible.get("page_size") === "12") visible.delete("page_size");
  const query = visible.toString();
  window.history.replaceState(null, "", `/history${query ? `?${query}` : ""}`);
}

function renderRuns(items) {
  runsContainer.innerHTML = items
    .map((run) => {
      const counts = run.counts || {};
      return `
        <article class="history-run-card">
          <div class="history-run-heading">
            <div>
              <small>${escapeHtml(typeLabel(run.target_type))}</small>
              <h2>${escapeHtml(run.target_ip || "未知目标")}</h2>
            </div>
            <div class="history-run-statuses">
              <span><small>原始</small>${statusMarkup(run.collection_status)}</span>
              <span><small>有效</small>${statusMarkup(run.assessment_status)}</span>
            </div>
          </div>
          <p class="history-run-time">${escapeHtml(formatTime(run.started_at))}</p>
          <div class="history-run-counts">
            <span><b>${Number(counts.success || 0)}</b> 成功</span>
            <span><b>${Number(counts.failed || 0)}</b> 失败</span>
            <span><b>${Number(counts.not_applicable || 0)}</b> 不适用</span>
            <span><b>${Number(counts.skipped || 0)}</b> 跳过</span>
          </div>
          <a class="run-analysis-link" href="/runs/${encodeURIComponent(run.run_id)}">
            查看分析详情 →
          </a>
        </article>
      `;
    })
    .join("");
}

async function loadHistory(page = 1) {
  const requestGeneration = ++historyRequestGeneration;
  loading.hidden = false;
  errorPanel.hidden = true;
  runsContainer.hidden = true;
  emptyPanel.hidden = true;
  pagination.hidden = true;
  const parameters = queryParameters(page);
  try {
    const response = await fetch(`/api/history?${parameters}`, {
      cache: "no-store",
    });
    if (!response.ok) {
      const payload = await response.json().catch(() => ({}));
      throw new Error(payload.detail || `历史接口返回 ${response.status}`);
    }
    const history = await response.json();
    if (requestGeneration !== historyRequestGeneration) return;
    currentPage = Number(history.page || 1);
    totalPages = Number(history.pages || 0);
    totalElement.textContent = Number(history.total || 0);
    loading.hidden = true;
    parameters.set("page", String(currentPage));
    syncUrl(parameters);
    if (!history.items.length) {
      emptyPanel.hidden = false;
      return;
    }
    renderRuns(history.items);
    runsContainer.hidden = false;
    pageLabel.textContent = `第 ${currentPage} / ${totalPages} 页`;
    previousButton.disabled = currentPage <= 1;
    nextButton.disabled = currentPage >= totalPages;
    pagination.hidden = totalPages <= 1;
  } catch (error) {
    if (requestGeneration !== historyRequestGeneration) return;
    loading.hidden = true;
    errorMessage.textContent = error.message || "无法读取历史采集记录。";
    errorPanel.hidden = false;
  }
}

function restoreFiltersFromUrl() {
  const parameters = new URLSearchParams(window.location.search);
  typeInput.value = parameters.get("target_type") || "";
  ipInput.value = parameters.get("target_ip") || "";
  statusInput.value = parameters.get("status") || "";
  const requestedSize = parameters.get("page_size") || "12";
  if (["12", "24", "48"].includes(requestedSize)) {
    pageSizeInput.value = requestedSize;
  }
  const requestedPage = Number(parameters.get("page") || 1);
  return Number.isInteger(requestedPage) && requestedPage > 0
    ? requestedPage
    : 1;
}

filters.addEventListener("submit", (event) => {
  event.preventDefault();
  loadHistory(1);
});

document.querySelector("#history-reset").addEventListener("click", () => {
  filters.reset();
  loadHistory(1);
});
document.querySelector("#history-retry").addEventListener("click", () => {
  loadHistory(currentPage);
});
previousButton.addEventListener("click", () => {
  if (currentPage > 1) loadHistory(currentPage - 1);
});
nextButton.addEventListener("click", () => {
  if (currentPage < totalPages) loadHistory(currentPage + 1);
});

loadHistory(restoreFiltersFromUrl());
