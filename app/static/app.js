const SUMMARY_ENDPOINT = "/api/public/summary";
const REFRESH_MS = 30000;
// Ranges longer than a day read many more rows, so they refresh less often.
const LONG_REFRESH_MS = 300000;
let refreshInProgress = false;
let hasLoadedSummary = false;
let latestSummary = null;
let summaryReceivedAt = 0;
let summaryUnavailable = false;
let interactionsReady = false;

// Longer ranges are summed into bigger buckets so the bars stay readable.
const RANGES = [
  { id: "6h", hours: 6, label: "Last 6 hours", short: "6h", group: 1 },
  { id: "12h", hours: 12, label: "Last 12 hours", short: "12h", group: 1 },
  { id: "24h", hours: 24, label: "Last 24 hours", short: "24h", group: 1 },
  { id: "2d", hours: 48, label: "Last 2 days", short: "2d", group: 1 },
  { id: "7d", hours: 168, label: "Last 7 days", short: "7d", group: 6 },
];
const DEFAULT_RANGE = RANGES[2];
const PER = { 1: "hour", 6: "6 hours" };
// Ranges this server refused (it caps history with NIDS_MAX_HISTORY_HOURS).
const unavailableRanges = new Set();
let range = initialRange();

const LABEL_META = [
  { key: "BENIGN", name: "Benign", className: "is-benign" },
  { key: "BOTNET", name: "Botnet", className: "is-botnet", attack: true },
  { key: "BRUTE_FORCE", name: "Brute force", className: "is-brute", attack: true },
  { key: "DOS_DDOS", name: "DoS / DDoS", className: "is-dos", attack: true },
  { key: "OTHER_ATTACK", name: "Other attack", className: "is-other", attack: true },
  { key: "UNVALIDATED", name: "Unvalidated", className: "is-unvalidated" },
];
const ATTACK_META = LABEL_META.filter(({ attack }) => attack);

// Why flows are unvalidated (the stored validation_reason), in words for the dashboard.
const UNVALIDATED_REASON_NAMES = {
  icmpv6_detection_not_validated: "ICMPv6",
  botnet_detection_not_validated: "Botnet predictions",
  window_not_warm: "Sensor warming up",
  window_degraded: "Window degraded",
  no_v2_features: "No model features",
  v2_unavailable: "Model unavailable",
};

// Time series panels: what each one plots, which series are hidden, and where its last drawing put things.
const charts = {};
const hiddenSeries = {};
const chartGeometry = {};
const CHART_IDS = ["chart-flows", "chart-attacks", "chart-probes", "chart-unvalidated"];

const metaFor = (key) => LABEL_META.find((meta) => meta.key === key);
const isCount = (value) => Number.isSafeInteger(value) && value >= 0;

function initialRange() {
  const wanted = typeof location === "object" && location ? new URLSearchParams(location.search).get("range") : null;
  return RANGES.find(({ id }) => id === wanted) || DEFAULT_RANGE;
}

function formatNumber(value) {
  return new Intl.NumberFormat().format(Number(value || 0));
}

function formatCompact(value) {
  return new Intl.NumberFormat(undefined, { notation: "compact", maximumFractionDigits: 1 }).format(Number(value || 0));
}

function formatShare(part, whole) {
  if (!(whole > 0)) return "—";
  const share = (part / whole) * 100;
  return `${share.toFixed(part > 0 && share < 1 ? 3 : 1)}%`;
}

const validDate = (value) => Boolean(value) && Number.isFinite(Date.parse(value));

function formatTime(value) {
  return new Date(value).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", hour12: false });
}

function formatDay(value) {
  return new Date(value).toLocaleDateString([], { year: "numeric", month: "short", day: "numeric" });
}

function formatTick(value, long) {
  if (!long) return formatTime(value);
  return `${new Date(value).toLocaleDateString([], { month: "2-digit", day: "2-digit" })} ${formatTime(value)}`;
}

function formatTipTime(value) {
  return new Date(value).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", hour12: false });
}

function formatAgo(ms) {
  const seconds = Math.max(0, ms / 1000);
  if (seconds < 60) return `${Math.round(seconds)} s ago`;
  if (seconds < 3600) return `${Math.round(seconds / 60)} min ago`;
  if (seconds < 172800) return `${Math.round(seconds / 3600)} h ago`;
  return `${Math.round(seconds / 86400)} days ago`;
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
}

function setText(id, value) {
  const node = document.getElementById(id);
  if (node) node.textContent = value;
}

function setHtml(id, value) {
  const node = document.getElementById(id);
  if (node) node.innerHTML = value;
}

const sumCounts = (counts, metas = LABEL_META) => metas.reduce((sum, { key }) => sum + Number(counts[key] || 0), 0);

/** Per-class totals across the hourly buckets (the selected range plus the hour in progress). */
function hourlyTotals(hourly) {
  const totals = Object.fromEntries(LABEL_META.map(({ key }) => [key, 0]));
  hourly.forEach((bucket) => LABEL_META.forEach(({ key }) => { totals[key] += Number(bucket.counts[key] || 0); }));
  return totals;
}

const SCAN_COUNTS = ["requests", "distinct_uris", "probe_paths", "not_found", "connections", "succeeded"];

/** Web probe counts, or null when the server sends none or sends something malformed. Scans are optional: an older
 * server sends none, and a malformed list is dropped (scans null) rather than the whole panel. */
function validProbes(probes) {
  if (!probes || !["recent_requests", "recent_clients", "history_requests", "history_clients"]
    .every((key) => isCount(probes[key]))) return null;
  const hourly = Array.isArray(probes.hourly)
    && probes.hourly.every((bucket) => bucket && isCount(bucket.requests) && Number.isFinite(Date.parse(bucket.bucket_start)))
    ? probes.hourly : [];
  const scans = isCount(probes.history_scans) && Array.isArray(probes.scans)
    && probes.scans.every((scan) => scan && validDate(scan.started_at) && Number.isFinite(scan.duration_seconds)
      && SCAN_COUNTS.every((key) => isCount(scan[key])))
    ? probes.scans : null;
  return { ...probes, hourly, scans };
}

function formatDuration(seconds) {
  if (seconds < 60) return `${Math.max(0, Math.round(seconds))} s`;
  if (seconds < 3600) return `${Math.round(seconds / 60)} min`;
  return `${(seconds / 3600).toFixed(1)} h`;
}

/** Per-sensor rows, or null when the server sends none or sends something malformed. */
function validSensors(sensors) {
  const valid = Array.isArray(sensors) && sensors.every((sensor) => sensor && typeof sensor.source === "string"
    && (sensor.lag_seconds === null || isCount(sensor.lag_seconds)));
  return valid ? sensors : null;
}

const clientsText = (n) => `${formatNumber(n)} client${n === 1 ? "" : "s"}`;

/**
 * Sums consecutive hourly buckets into groups of `size` hours, aligned to local time.
 * Returns the group start times and a function that sums a value over each group.
 */
function group(buckets, size) {
  if (size === 1) return { times: buckets.map((b) => b.bucket_start), values: (fn) => buckets.map(fn) };
  const groups = [];
  buckets.forEach((bucket) => {
    const start = new Date(bucket.bucket_start);
    const key = `${start.toDateString()} ${Math.floor(start.getHours() / size)}`;
    if (!groups.length || groups.at(-1).key !== key) groups.push({ key, start: bucket.bucket_start, items: [] });
    groups.at(-1).items.push(bucket);
  });
  // The range rarely starts on a group boundary; a partial first group would look like a dip.
  if (groups.length > 1 && groups[0].items.length < size) groups.shift();
  return {
    times: groups.map((g) => g.start),
    values: (fn) => groups.map((g) => g.items.reduce((sum, bucket) => sum + fn(bucket), 0)),
  };
}

// ---------- status ----------

function renderActivityStatus() {
  const badge = document.getElementById("activity-badge");
  if (!badge) return;

  let state = "waiting";
  let label = "Waiting for data";
  let detail = "No classified flows received yet.";
  let ageText = "";
  const lastClassified = latestSummary?.last_observed_at;
  const observedAt = lastClassified ? Date.parse(lastClassified) : NaN;
  const generatedAt = Date.parse(latestSummary?.generated_at);
  const configuredThreshold = Number(latestSummary?.stale_after_seconds);
  const threshold = Number.isFinite(configuredThreshold) && configuredThreshold > 0
    ? configuredThreshold : 300;
  const thresholdLabel = threshold % 60 === 0
    ? `${threshold / 60} minute${threshold === 60 ? "" : "s"}`
    : `${threshold} second${threshold === 1 ? "" : "s"}`;

  if (Number.isFinite(observedAt) && Number.isFinite(generatedAt)) {
    // Use the server clock for event age, then advance it between responses.
    const age = Math.max(0, generatedAt - observedAt) + Math.max(0, Date.now() - summaryReceivedAt);
    const stale = age >= threshold * 1000;
    state = stale ? "stale" : "live";
    label = stale ? "Stale" : "Live";
    ageText = `· latest flow ${formatAgo(age)}`;
    detail = stale
      ? `No classified flows in the last ${thresholdLabel}. Traffic may be quiet or the sensor may be delayed.`
      : "";
  } else if (Number(latestSummary?.lifetime_flows) > 0) {
    state = "stale";
    label = "Stale";
    detail = "No recent flow timestamp is available.";
  }

  if (summaryUnavailable) {
    state = hasLoadedSummary ? "stale" : "waiting";
    label = hasLoadedSummary ? "Stale" : "Waiting for data";
    detail = hasLoadedSummary
      ? "Unable to confirm recent activity. Showing the last successful update; retrying automatically."
      : "Unable to load the summary. Retrying automatically.";
  }

  badge.className = `live is-${state}`;
  badge.textContent = label;
  setText("latest-flow", ageText);
  setText("activity-detail", detail);
}

// ---------- overview ----------

function sparkSvg(values) {
  if (values.length < 2) return "";
  const max = Math.max(...values, 1);
  const points = values.map((value, i) => `${((i / (values.length - 1)) * 100).toFixed(2)},${(40 - (value / max) * 36).toFixed(2)}`).join(" ");
  return `<svg viewBox="0 0 100 40" preserveAspectRatio="none" aria-hidden="true">`
    + `<polygon class="fill" points="0,40 ${points} 100,40"/>`
    + `<polyline class="line" points="${points}" vector-effect="non-scaling-stroke"/></svg>`;
}

function renderRangeTitles(shown) {
  const per = PER[shown.group];
  const titles = {
    "title-flows": `Flows · ${shown.short}`,
    "title-attacks": `Suspected attacks · ${shown.short}`,
    "title-unvalidated": `Unvalidated · ${shown.short}`,
    "title-probes": `Web probes · ${shown.short}`,
    "title-scans": `Web scans · ${shown.short}`,
    "title-classes": `Classifications · ${shown.short}`,
    "title-reasons": `By reason · ${shown.short}`,
    "title-chart-flows": `Flows per ${per}`,
    "title-chart-attacks": `Suspected attacks per ${per}`,
    "title-chart-probes": `Web probe requests per ${per}`,
    "title-chart-unvalidated": `Unvalidated flows per ${per}`,
  };
  Object.entries(titles).forEach(([id, text]) => setText(id, text));
}

function renderStats(data, shown) {
  const totals = hourlyTotals(data.hourly);
  const flows = sumCounts(totals);
  const attacks = sumCounts(totals, ATTACK_META);
  const groups = group(data.hourly, shown.group);

  setText("metric-flows", formatCompact(flows));
  setText("metric-flows-detail", flows > 0 ? `${formatShare(totals.BENIGN, flows)} benign` : "No flows yet");
  setHtml("spark-flows", sparkSvg(groups.values((bucket) => sumCounts(bucket.counts))));

  setText("metric-attacks", formatNumber(attacks));
  setText("metric-attacks-detail", attacks > 0
    ? ATTACK_META.filter(({ key }) => totals[key] > 0).map(({ key, name }) => `${name} ${formatNumber(totals[key])}`).join(" · ")
    : "None predicted");
  setHtml("spark-attacks", attacks > 0 ? sparkSvg(groups.values((bucket) => sumCounts(bucket.counts, ATTACK_META))) : "");
  const attackPanel = document.getElementById("stat-attacks");
  if (attackPanel) attackPanel.className = `panel stat ${attacks > 0 ? "is-alert" : "is-quiet"}`;

  setText("metric-unvalidated", formatCompact(totals.UNVALIDATED));
  setText("metric-unvalidated-detail", flows > 0 ? `${formatShare(totals.UNVALIDATED, flows)} of flows` : "None");
  setHtml("spark-unvalidated", sparkSvg(groups.values((bucket) => Number(bucket.counts.UNVALIDATED || 0))));

  const probes = validProbes(data.web_probes);
  setText("metric-probes", probes ? formatNumber(probes.history_requests) : "—");
  const scanCount = probes && probes.scans ? ` · ${formatNumber(probes.history_scans)} ${probes.history_scans === 1 ? "scan" : "scans"}` : "";
  setText("metric-probes-detail", probes ? `from ${clientsText(probes.history_clients)}${scanCount}` : "Not reported");
  setHtml("spark-probes", probes ? sparkSvg(group(probes.hourly, shown.group).values((bucket) => bucket.requests)) : "");

  const sensors = validSensors(data.sensors);
  const sensorPanel = document.getElementById("stat-sensor");
  if (sensors && sensors.length) {
    const stale = sensors.some((sensor) => sensor.stale === true);
    const lags = sensors.map((sensor) => sensor.lag_seconds).filter((lag) => lag !== null);
    setText("sensor-state", stale ? "Stale" : "Up");
    setText("sensor-detail", lags.length ? `lag ${formatNumber(Math.max(...lags))} s` : "");
    if (sensorPanel) sensorPanel.className = `panel stat ${stale ? "is-stale" : "is-live"}`;
  } else {
    setText("sensor-state", "—");
    setText("sensor-detail", sensors ? "No sensor has reported yet" : "Not reported");
    if (sensorPanel) sensorPanel.className = "panel stat is-waiting";
  }
}

function renderModelSince(provenance) {
  // The server notes when the operational model last changed; show that date when it parses.
  const match = typeof provenance === "string" ? / -> \S+ at (\S+)/.exec(provenance) : null;
  const valid = Boolean(match) && validDate(match[1]);
  const node = document.getElementById("model-since");
  if (node) node.hidden = !valid;
  if (valid) setText("model-since", `in service since ${formatDay(match[1])}`);
}

// ---------- time series ----------

function niceMax(value) {
  if (value <= 0) return 4;
  // Small counts get whole-number gridlines (the axis has four steps).
  if (value <= 16) return Math.ceil(value / 4) * 4;
  const magnitude = Math.pow(10, Math.floor(Math.log10(value)));
  // Steps that split into four whole-number gridlines.
  for (const step of [1, 2, 4, 6, 8, 10]) if (step * magnitude >= value) return step * magnitude;
  return 10 * magnitude;
}

/** The four time series panels for a summary, grouped for the range it was requested with. */
function chartConfigs(data, shown) {
  const groups = group(data.hourly, shown.group);
  const layer = (key) => ({ ...metaFor(key), values: groups.values((bucket) => Number(bucket.counts[key] || 0)) });
  const probes = validProbes(data.web_probes);
  const probeHourly = probes ? probes.hourly : [];
  const probeGroups = group(probeHourly, shown.group);
  const long = shown.hours > 24;
  return {
    "chart-flows": { title: "Flows", kind: "area", stacked: true, long, times: groups.times, series: [layer("BENIGN"), layer("UNVALIDATED")] },
    "chart-attacks": { title: "Suspected attacks", kind: "bars", stacked: true, long, times: groups.times, series: ATTACK_META.map(({ key }) => layer(key)) },
    "chart-probes": {
      title: "Web probe requests", kind: "bars", long, times: probeGroups.times,
      series: [{ key: "PROBE", name: "Requests", className: "is-probe", values: probeGroups.values((bucket) => bucket.requests) }],
      // Unique clients only add up within one hour.
      extra: shown.group === 1 ? (t) => ({ name: "Clients", value: Number(probeHourly[t]?.clients || 0) }) : null,
      empty: probes ? "No web probe requests in this range." : "Web probe counts are not reported.",
    },
    "chart-unvalidated": { title: "Unvalidated flows", kind: "area", long, times: groups.times, series: [layer("UNVALIDATED")] },
  };
}

function renderLegend(id) {
  const conf = charts[id];
  const hidden = hiddenSeries[id] || new Set();
  setHtml(id.replace("chart-", "legend-"), conf.series.map(({ key, name, className, values }) => {
    const mean = values.reduce((a, b) => a + b, 0) / (values.length || 1);
    return `<tr class="${className}${hidden.has(key) ? " off" : ""}" data-key="${key}" title="Click to hide or show">`
      + `<td><span class="sw"></span>${escapeHtml(name)}</td><td>${formatNumber(values.at(-1) || 0)}</td>`
      + `<td>${formatNumber(Math.round(mean))}</td><td>${formatNumber(Math.max(0, ...values))}</td></tr>`;
  }).join(""));
}

function drawChart(id) {
  const plot = document.getElementById(id);
  const conf = charts[id];
  if (!plot || !conf) return;
  plot.innerHTML = "";
  chartGeometry[id] = null;
  const n = conf.times.length;
  if (n === 0) {
    plot.innerHTML = `<div class="empty-state">${conf.empty || "Hourly activity will appear after the first classified flows are stored."}</div>`;
    return;
  }

  const hidden = hiddenSeries[id] || new Set();
  const shown = conf.series.filter(({ key }) => !hidden.has(key));
  const width = plot.clientWidth || 800;
  const height = plot.clientHeight || 200;
  const padL = 48;
  const padR = 6;
  const padT = 6;
  const padB = 22;
  const tops = conf.times.map((_, t) => conf.stacked
    ? shown.reduce((sum, { values }) => sum + values[t], 0)
    : Math.max(0, ...shown.map(({ values }) => values[t])));
  const max = niceMax(Math.max(0, ...tops));
  const bars = conf.kind === "bars" || n === 1;
  const x = (t) => padL + (bars ? (t + 0.5) / n : t / (n - 1)) * (width - padL - padR);
  const y = (value) => padT + (1 - value / max) * (height - padT - padB);

  let svg = "";
  // Area fills fade out downwards in the series color.
  if (!bars) {
    svg += `<defs>${shown.map(({ className }, i) => `<linearGradient id="g-${id}-${i}" class="${className}" x1="0" x2="0" y1="0" y2="1">`
      + `<stop offset="0" class="g0"/><stop offset="1" class="g1"/></linearGradient>`).join("")}</defs>`;
  }
  for (let k = 0; k <= 4; k += 1) {
    const value = (max / 4) * k;
    svg += `<line class="gl" x1="${padL}" x2="${width - padR}" y1="${y(value)}" y2="${y(value)}"/>`
      + `<text class="ax" x="${padL - 8}" y="${y(value) + 4}" text-anchor="end">${formatCompact(value)}</text>`;
  }
  // Label every few buckets, keeping enough room between labels for the text.
  const slot = (width - padL - padR) / Math.max(1, n - 1);
  const minGap = conf.long ? 96 : 64;
  const every = [1, 2, 3, 4, 6, 8, 12, 24, 48].find((step) => step * slot >= minGap) || 48;
  conf.times.forEach((time, t) => {
    if (t % every !== 0) return;
    // Labels at the edges are aligned inward so they are not clipped.
    const anchor = x(t) > width - 30 ? "end" : x(t) < padL + 20 ? "start" : "middle";
    svg += `<line class="gl" x1="${x(t)}" x2="${x(t)}" y1="${padT}" y2="${height - padB}"/>`
      + `<text class="ax" x="${x(t)}" y="${height - 4}" text-anchor="${anchor}">${formatTick(time, conf.long)}</text>`;
  });

  if (bars) {
    const barWidth = Math.max(2, ((width - padL - padR) / n) * 0.7);
    conf.times.forEach((_, t) => {
      let stacked = 0;
      shown.forEach(({ className, values }) => {
        const value = values[t];
        if (!value) return;
        // Small counts keep a visible minimum height.
        const base = conf.stacked ? stacked : 0;
        const h = Math.max(2, y(base) - y(base + value));
        svg += `<rect class="bar ${className}" x="${(x(t) - barWidth / 2).toFixed(1)}" y="${(y(base) - h).toFixed(1)}" width="${barWidth.toFixed(1)}" height="${h.toFixed(1)}"/>`;
        stacked += value;
      });
    });
  } else {
    let base = new Array(n).fill(0);
    shown.forEach(({ className, values }, i) => {
      const top = values.map((value, t) => (conf.stacked ? base[t] : 0) + value);
      const upper = top.map((value, t) => `${x(t).toFixed(1)},${y(value).toFixed(1)}`).join(" ");
      const lower = (conf.stacked ? base : base.map(() => 0)).map((value, t) => `${x(t).toFixed(1)},${y(value).toFixed(1)}`).reverse().join(" ");
      svg += `<polygon points="${upper} ${lower}" fill="url(#g-${id}-${i})"/><polyline class="line ${className}" points="${upper}"/>`;
      if (conf.stacked) base = top;
    });
  }
  svg += `<line class="xh" x1="0" x2="0" y1="${padT}" y2="${height - padB}"/>`;
  if (!bars) svg += shown.map(({ key, className }) => `<circle class="dot ${className}" r="4" data-key="${key}"/>`).join("");

  const host = document.createElement("div");
  host.className = "chart-svg";
  host.innerHTML = `<svg role="img" aria-label="${conf.title}" width="${width}" height="${height}">${svg}</svg>`;
  plot.appendChild(host);
  chartGeometry[id] = { n, padL, padR, width, bars, x, y, shown };
}

function chartTooltip(id, t) {
  const conf = charts[id];
  const geometry = chartGeometry[id];
  const row = (className, name, value, swatch = true) =>
    `<div class="t-r ${className}"><span>${swatch ? '<i class="t-sw"></i>' : ""}${escapeHtml(name)}</span><b class="num">${formatNumber(value)}</b></div>`;
  // Stacked series read top to bottom, like the chart.
  let rows = geometry.shown.slice().reverse().map(({ name, className, values }) => row(className, name, values[t])).join("");
  if (conf.extra) {
    const extra = conf.extra(t);
    rows += row("", extra.name, extra.value, false);
  }
  const last = t === geometry.n - 1 ? " · in progress" : "";
  return `<div class="t-h">${formatTipTime(conf.times[t])}${last}</div>${rows || '<div class="subtle">All series hidden</div>'}`;
}

function renderCharts(data, shown) {
  Object.entries(chartConfigs(data, shown)).forEach(([id, conf]) => {
    charts[id] = conf;
    renderLegend(id);
    drawChart(id);
  });
}

// ---------- panels ----------

function gaugeRow(className, name, value, whole) {
  const row = document.createElement("div");
  row.className = `bg-row ${className}`;
  const width = whole > 0 ? (value / whole) * 100 : 0;
  row.innerHTML = `<span class="nm" title="${name}">${name}</span>`
    + `<span class="track"><span class="fill${value > 0 ? "" : " is-none"}" style="width: ${width}%"></span></span>`
    + `<span class="v${value > 0 ? "" : " is-zero"}" title="${formatNumber(value)} (${formatShare(value, whole)})">${formatCompact(value)}</span>`;
  return row;
}

function renderClassList(hourly) {
  const list = document.getElementById("class-list");
  if (!list) return;
  list.innerHTML = "";
  const totals = hourlyTotals(hourly);
  // Bars share one scale, set by the largest class.
  const top = Math.max(1, ...Object.values(totals));
  LABEL_META.forEach(({ key, name, className }) => list.appendChild(gaugeRow(className, name, totals[key], top)));
}

function renderUnvalidatedReasons(reasons) {
  // Optional block: an older server sends no breakdown.
  const list = document.getElementById("reason-list");
  if (!list) return;
  list.innerHTML = "";
  const valid = reasons && typeof reasons === "object" && !Array.isArray(reasons)
    && Object.values(reasons).every((value) => isCount(value));
  if (!valid) {
    list.innerHTML = `<div class="empty-state">No breakdown reported.</div>`;
    return;
  }
  const entries = Object.entries(reasons)
    .filter(([, count]) => count > 0)
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
  if (entries.length === 0) {
    list.innerHTML = `<div class="empty-state">No unvalidated flows.</div>`;
    return;
  }
  const top = entries[0][1];
  entries.forEach(([reason, count]) => {
    const fallback = reason.replace(/_/g, " ");
    const name = UNVALIDATED_REASON_NAMES[reason] || fallback.charAt(0).toUpperCase() + fallback.slice(1);
    list.appendChild(gaugeRow("is-unvalidated", escapeHtml(name), count, top));
  });
}

function renderLabelList(retainedCounts) {
  const list = document.getElementById("label-list");
  if (!list) return;
  list.innerHTML = "";
  const whole = sumCounts(retainedCounts);
  LABEL_META.forEach(({ key, name, className }) => {
    const row = document.createElement("tr");
    row.innerHTML = `
      <td class="${className}"><span class="dotc"></span>${name}</td>
      <td class="n${retainedCounts[key] > 0 ? "" : " subtle"}">${formatNumber(retainedCounts[key])}</td>
      <td class="n">${formatShare(retainedCounts[key], whole)}</td>
    `;
    list.appendChild(row);
  });
}

function renderSensors(sensors) {
  // Optional block: per-sensor source and lag, shown when the server reports them.
  const list = document.getElementById("sensor-list");
  if (!list) return;
  list.innerHTML = "";
  const valid = validSensors(sensors);
  if (!valid || valid.length === 0) {
    list.innerHTML = `<tr><td colspan="4" class="subtle">${valid ? "No sensor has reported yet." : "Sensor details are not reported."}</td></tr>`;
    return;
  }
  valid.forEach((sensor) => {
    const state = typeof sensor.stale === "boolean"
      ? `<td class="state ${sensor.stale ? "is-stale" : "is-live"}">${sensor.stale ? "Stale" : "Up"}</td>` : "<td>—</td>";
    const row = document.createElement("tr");
    row.innerHTML = `
      <td class="mono">${escapeHtml(sensor.source)}</td>
      ${state}
      <td class="n">${sensor.lag_seconds === null ? "—" : `${formatNumber(sensor.lag_seconds)} s`}</td>
      <td class="n">${validDate(sensor.last_observed_at) ? formatTime(sensor.last_observed_at) : "—"}</td>
    `;
    list.appendChild(row);
  });
}

function renderScans(webProbes) {
  // Web scans grouped by the server (app/web_scans.py), newest first; the server sends at most 20.
  const list = document.getElementById("scan-list");
  if (!list) return;
  list.innerHTML = "";
  const probes = validProbes(webProbes);
  const scans = probes ? probes.scans : null;
  if (!scans || scans.length === 0) {
    list.innerHTML = `<tr><td colspan="8" class="subtle">${scans ? "No web scans in this range." : "Web scans are not reported."}</td></tr>`;
    return;
  }
  scans.forEach((scan) => {
    const row = document.createElement("tr");
    const served = scan.succeeded > 0
      ? `<td class="state is-alert">${formatNumber(scan.succeeded)} probe ${scan.succeeded === 1 ? "path" : "paths"}</td>`
      : `<td class="subtle">Nothing</td>`;
    row.innerHTML = `
      <td>${formatTipTime(scan.started_at)}</td>
      <td class="n">${formatNumber(scan.requests)}</td>
      <td class="n hide-sm">${formatNumber(scan.distinct_uris)}</td>
      <td class="n hide-sm">${formatNumber(scan.probe_paths)}</td>
      <td class="n">${formatNumber(scan.not_found)}</td>
      <td class="n hide-sm">${formatNumber(scan.connections)}</td>
      <td class="n hide-sm">${formatDuration(scan.duration_seconds)}</td>
      ${served}
    `;
    list.appendChild(row);
  });
  if (probes.history_scans > scans.length) {
    const more = document.createElement("tr");
    more.innerHTML = `<td colspan="8" class="subtle">Latest ${formatNumber(scans.length)} of ${formatNumber(probes.history_scans)} scans.</td>`;
    list.appendChild(more);
  }
}

function renderSystem(data) {
  setText("model-name", data.model_name);
  renderModelSince(data.counter_provenance);
  setText("lifetime-flows", formatCompact(data.lifetime_flows));
  setText("lifetime-flows-full", formatNumber(data.lifetime_flows));
  setText("lifetime-packets", formatCompact(data.lifetime_packets));
  setText("lifetime-packets-full", formatNumber(data.lifetime_packets));
  setText("retained-flows", formatCompact(data.total_events));
  setText("total-events", formatNumber(data.total_events));
  const retentionHours = Number(data.retention_hours);
  const retentionWindow = retentionHours % 24 === 0 ? `last ${retentionHours / 24} days` : `last ${retentionHours} hours`;
  setText("retained-window", retentionWindow);
  setText("label-totals-window", retentionWindow);
  const processed = validDate(data.last_processed_at);
  setText("last-classified", processed ? formatTime(data.last_processed_at) : "Waiting for data");
  setText("last-classified-date", processed ? new Date(data.last_processed_at).toLocaleString() : "");
  const refreshButton = document.getElementById("refresh-btn");
  if (refreshButton) refreshButton.title = `Refresh (updated ${new Date(data.generated_at).toLocaleTimeString()})`;
}

// ---------- interactions ----------

function renderRangeMenu() {
  setText("range-label", range.label);
  const menu = document.getElementById("range-menu");
  if (!menu || typeof menu.querySelectorAll !== "function") return;
  menu.querySelectorAll("[data-range]").forEach((button) => {
    button.setAttribute("aria-checked", String(button.dataset.range === range.id));
    button.disabled = unavailableRanges.has(button.dataset.range);
    if (button.disabled) button.title = "Not available on this server";
  });
}

function selectRange(id) {
  const next = RANGES.find((option) => option.id === id);
  if (!next || next === range || unavailableRanges.has(id)) return;
  range = next;
  syncRangeUrl();
  renderRangeMenu();
  refresh();
}

/** Keeps the selected range in the address bar so a reload or shared link opens it. */
function syncRangeUrl() {
  if (typeof history !== "object" || !history || typeof URL !== "function") return;
  const url = new URL(location.href);
  if (range === DEFAULT_RANGE) url.searchParams.delete("range");
  else url.searchParams.set("range", range.id);
  history.replaceState(null, "", url);
}

function positionTip(tip, event) {
  const size = tip.getBoundingClientRect();
  tip.style.left = `${Math.min(window.innerWidth - size.width - 8, Math.max(8, event.clientX + 14))}px`;
  tip.style.top = `${event.clientY + size.height + 20 > window.innerHeight ? event.clientY - size.height - 12 : event.clientY + 14}px`;
}

function setUpChart(id, tip) {
  const plot = document.getElementById(id);
  const legend = document.getElementById(id.replace("chart-", "legend-"));
  const hide = () => {
    tip.classList.remove("on");
    plot.querySelectorAll(".xh, .dot").forEach((node) => node.classList.remove("on"));
  };
  plot.addEventListener("mousemove", (event) => {
    const geometry = chartGeometry[id];
    if (!geometry) return;
    const box = plot.getBoundingClientRect();
    const fraction = (event.clientX - box.left - geometry.padL) / (geometry.width - geometry.padL - geometry.padR);
    if (fraction < -0.02 || fraction > 1.02) { hide(); return; }
    const t = Math.max(0, Math.min(geometry.n - 1, geometry.bars
      ? Math.floor(fraction * geometry.n) : Math.round(fraction * (geometry.n - 1))));
    const line = plot.querySelector(".xh");
    if (line) {
      line.setAttribute("x1", geometry.x(t));
      line.setAttribute("x2", geometry.x(t));
      line.classList.add("on");
    }
    let stacked = 0;
    plot.querySelectorAll(".dot").forEach((dot) => {
      const series = geometry.shown.find(({ key }) => key === dot.dataset.key);
      if (!series) return;
      stacked = charts[id].stacked ? stacked + series.values[t] : series.values[t];
      dot.setAttribute("cx", geometry.x(t));
      dot.setAttribute("cy", geometry.y(stacked));
      dot.classList.add("on");
    });
    tip.innerHTML = chartTooltip(id, t);
    tip.classList.add("on");
    positionTip(tip, event);
  });
  plot.addEventListener("mouseleave", hide);
  window.addEventListener("scroll", hide, { passive: true });

  if (legend) {
    legend.addEventListener("click", (event) => {
      const row = event.target.closest("[data-key]");
      if (!row || !charts[id]) return;
      const hidden = hiddenSeries[id] || (hiddenSeries[id] = new Set());
      if (hidden.has(row.dataset.key)) hidden.delete(row.dataset.key);
      else hidden.add(row.dataset.key);
      renderLegend(id);
      drawChart(id);
    });
  }

  if (typeof ResizeObserver === "function") {
    // A chart in a collapsed row has no width; it redraws when the row opens.
    let lastWidth = 0;
    new ResizeObserver(() => {
      if (plot.clientWidth === lastWidth) return;
      lastWidth = plot.clientWidth;
      drawChart(id);
    }).observe(plot);
  }
}

function setUpRangeMenu() {
  const button = document.getElementById("range-btn");
  const menu = document.getElementById("range-menu");
  if (!button || !menu) return;
  const items = () => [...menu.querySelectorAll("[data-range]:not(:disabled)")];
  const open = (show) => {
    menu.hidden = !show;
    button.setAttribute("aria-expanded", String(show));
    if (show) (menu.querySelector(`[data-range="${range.id}"]`) || items()[0])?.focus();
  };
  button.addEventListener("click", (event) => {
    event.stopPropagation();
    open(menu.hidden);
  });
  menu.addEventListener("click", (event) => {
    const item = event.target.closest("[data-range]");
    if (!item || item.disabled) return;
    open(false);
    button.focus();
    selectRange(item.dataset.range);
  });
  document.addEventListener("click", (event) => {
    if (!menu.hidden && !menu.contains(event.target)) open(false);
  });
  document.addEventListener("keydown", (event) => {
    if (menu.hidden) return;
    if (event.key === "Escape") {
      open(false);
      button.focus();
    } else if (event.key === "ArrowDown" || event.key === "ArrowUp") {
      event.preventDefault();
      const list = items();
      const at = list.indexOf(document.activeElement);
      list[(at + (event.key === "ArrowDown" ? 1 : list.length - 1)) % list.length]?.focus();
    }
  });
}

/** Chart hover, legend toggles, the range menu and the refresh button; installed once. */
function setUpInteractions() {
  const tip = document.getElementById("chart-tip");
  const first = document.getElementById(CHART_IDS[0]);
  if (interactionsReady || !tip || !first || typeof first.addEventListener !== "function") return;
  interactionsReady = true;
  CHART_IDS.forEach((id) => setUpChart(id, tip));
  setUpRangeMenu();
  renderRangeMenu();
  const refreshButton = document.getElementById("refresh-btn");
  refreshButton?.addEventListener("click", () => {
    refreshButton.classList.remove("spin");
    void refreshButton.offsetWidth;
    refreshButton.classList.add("spin");
    refresh();
  });
}

// ---------- data ----------

async function loadSummary(hours) {
  const controller = new AbortController();
  let timer;
  try {
    return await Promise.race([
      (async () => {
        const response = await fetch(`${SUMMARY_ENDPOINT}?hours=${hours}`, {
          cache: "no-store", signal: controller.signal,
        });
        if (!response.ok) {
          const error = new Error(`Status ${response.status}`);
          error.status = response.status;
          throw error;
        }
        return validateSummary(await response.json());
      })(),
      new Promise((_, reject) => {
        timer = setTimeout(() => {
          controller.abort();
          reject(new Error("Summary request timed out"));
        }, 10000);
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}

function validateSummary(data) {
  const count = (value) => Number.isSafeInteger(value) && value >= 0;
  const date = (value) => typeof value === "string" && Number.isFinite(Date.parse(value));
  const counts = (value) => value && typeof value === "object"
    && Object.keys(value).length === LABEL_META.length
    && LABEL_META.every(({ key }) => count(value[key]));
  if (!data || typeof data.model_name !== "string" || !date(data.generated_at)
      || !["lifetime_flows", "lifetime_packets", "total_events", "retained_packets"].every((key) => count(data[key]))
      || !["retention_hours", "recent_window_minutes", "stale_after_seconds"].every((key) => count(data[key]) && data[key] > 0)
      || !counts(data.retained_counts) || !counts(data.recent_counts)
      || !["last_observed_at", "last_processed_at"].every((key) => data[key] === null || date(data[key]))
      || !Array.isArray(data.warnings) || !data.warnings.every((item) => typeof item === "string")
      || !Array.isArray(data.hourly)
      || !data.hourly.every((bucket) => bucket && date(bucket.bucket_start) && counts(bucket.counts))
      || Object.values(data.retained_counts).reduce((a, b) => a + b, 0) !== data.total_events
      || data.total_events > data.lifetime_flows
      || LABEL_META.some(({ key }) => data.recent_counts[key] > data.retained_counts[key])) {
    throw new Error("Invalid summary response");
  }
  return data;
}

async function refresh() {
  renderActivityStatus();
  if (refreshInProgress) return;
  refreshInProgress = true;
  const requested = range;
  // A range picked while this request was out is loaded as soon as it returns.
  let again = false;
  try {
    const data = await loadSummary(requested.hours);
    if (requested !== range) {
      again = true;
      return;
    }
    latestSummary = data;
    summaryReceivedAt = Date.now();
    summaryUnavailable = false;
    renderRangeTitles(requested);
    renderStats(data, requested);
    renderCharts(data, requested);
    renderClassList(data.hourly);
    renderUnvalidatedReasons(data.history_unvalidated_reasons);
    renderScans(data.web_probes);
    renderLabelList(data.retained_counts);
    renderSensors(data.sensors);
    renderSystem(data);
    hasLoadedSummary = true;
    renderActivityStatus();
  } catch (error) {
    if (requested !== range) {
      again = true;
    } else if (error.status === 422 && requested !== DEFAULT_RANGE) {
      // This server keeps less history than the range asks for.
      unavailableRanges.add(requested.id);
      range = DEFAULT_RANGE;
      syncRangeUrl();
      renderRangeMenu();
      again = true;
    } else {
      summaryUnavailable = true;
      renderActivityStatus();
    }
  } finally {
    refreshInProgress = false;
    if (again) refresh();
  }
}

function tick() {
  if (range.hours > 24 && hasLoadedSummary && !summaryUnavailable && Date.now() - summaryReceivedAt < LONG_REFRESH_MS) {
    renderActivityStatus();
    return;
  }
  refresh();
}

setUpInteractions();
refresh();
window.setInterval(tick, REFRESH_MS);
