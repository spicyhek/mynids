const SUMMARY_ENDPOINT = "/api/public/summary";
const REFRESH_MS = 30000;
const HOURS = 24;

const LABEL_META = [
  { key: "BENIGN", target: "recent-benign", className: "is-benign" },
  { key: "BOTNET", target: "recent-botnet", className: "is-botnet" },
  { key: "DOS_DDOS", target: "recent-dos", className: "is-dos" },
  { key: "OTHER_ATTACK", target: "recent-other", className: "is-other" },
];

function formatNumber(value) {
  return new Intl.NumberFormat().format(Number(value || 0));
}

function formatDate(value) {
  if (!value) return "Waiting for data";
  const date = new Date(value);
  if (Number.isNaN(date.valueOf())) return "Waiting for data";
  return date.toLocaleString();
}

function setText(id, value) {
  const node = document.getElementById(id);
  if (node) node.textContent = value;
}

function renderLabelList(allTimeCounts, recentCounts) {
  const list = document.getElementById("label-list");
  if (!list) return;
  list.innerHTML = "";

  LABEL_META.forEach(({ key, className }) => {
    const row = document.createElement("div");
    row.className = "label-row";
    row.innerHTML = `
      <div class="label-row-heading">
        <span class="pill ${className}">${key.replace("_", " / ").toLowerCase()}</span>
        <strong>${formatNumber(allTimeCounts[key])}</strong>
      </div>
      <span class="meta-label">recent window: ${formatNumber(recentCounts[key])}</span>
    `;
    list.appendChild(row);
  });
}

function renderWarnings(warnings) {
  const list = document.getElementById("warning-list");
  if (!list) return;
  list.innerHTML = "";

  if (!Array.isArray(warnings) || warnings.length === 0) {
    list.innerHTML = `<div class="empty-state">No public warnings reported.</div>`;
    return;
  }

  warnings.forEach((warning) => {
    const item = document.createElement("div");
    item.className = "warning-item";
    item.textContent = warning;
    list.appendChild(item);
  });
}

function renderHourlyChart(hourly) {
  const chart = document.getElementById("hourly-chart");
  if (!chart) return;
  chart.innerHTML = "";

  if (!Array.isArray(hourly) || hourly.length === 0) {
    chart.innerHTML = `<div class="empty-state">Hourly activity will appear after the first classified flows are stored.</div>`;
    return;
  }

  const maxTotal = Math.max(
    ...hourly.map((bucket) => Object.values(bucket.counts || {}).reduce((sum, count) => sum + Number(count || 0), 0)),
    1
  );

  hourly.forEach((bucket) => {
    const total = Object.values(bucket.counts || {}).reduce((sum, count) => sum + Number(count || 0), 0);
    const bar = document.createElement("div");
    bar.className = "chart-row";
    bar.innerHTML = `
      <div class="chart-row-heading">
        <span>${new Date(bucket.bucket_start).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}</span>
        <strong>${formatNumber(total)}</strong>
      </div>
      <div class="chart-track">
        <div class="chart-fill" style="width: ${(total / maxTotal) * 100}%"></div>
      </div>
    `;
    chart.appendChild(bar);
  });
}

async function loadSummary() {
  const response = await fetch(`${SUMMARY_ENDPOINT}?hours=${HOURS}`, { cache: "no-store" });
  if (!response.ok) {
    throw new Error(`Status ${response.status}`);
  }
  return response.json();
}

async function refresh() {
  try {
    const data = await loadSummary();
    setText("model-name", data.model_name);
    setText("last-classified", formatDate(data.last_classified_at));
    setText("total-events", formatNumber(data.total_events));
    setText("recent-window-label", `Last ${data.recent_window_minutes} minutes`);

    LABEL_META.forEach(({ key, target }) => {
      setText(target, formatNumber((data.recent_counts || {})[key]));
    });

    renderLabelList(data.all_time_counts || {}, data.recent_counts || {});
    renderWarnings(data.warnings || []);
    renderHourlyChart(data.hourly || []);
  } catch (error) {
    setText("model-name", "Unavailable");
    setText("last-classified", "Unable to load summary");
    setText("total-events", "0");
    renderWarnings(["Unable to load the NIDS dashboard summary right now."]);
    renderHourlyChart([]);
  }
}

refresh();
window.setInterval(refresh, REFRESH_MS);
