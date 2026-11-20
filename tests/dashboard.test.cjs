const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");

const script = fs.readFileSync(path.join(__dirname, "../app/static/app.js"), "utf8");

function dashboard(fetch, clock = Date, timers = { setTimeout, clearTimeout }) {
  const nodes = new Map();
  const createNode = () => ({
    textContent: "",
    innerHTML: "",
    children: [],
    classList: { add() {} },
    appendChild(node) { this.children.push(node); },
  });
  const context = vm.createContext({
    fetch,
    AbortController,
    ...timers,
    Intl,
    Date: clock,
    document: {
      getElementById(id) {
        if (!nodes.has(id)) nodes.set(id, createNode());
        return nodes.get(id);
      },
      createElement: createNode,
    },
    window: { setInterval() {} },
  });
  vm.runInContext(script, context);
  return {
    context, nodes,
    refresh: () => vm.runInContext("refresh()", context),
    selectRange: (id) => vm.runInContext(`selectRange(${JSON.stringify(id)})`, context),
    tick: () => vm.runInContext("tick()", context),
    get: (expression) => vm.runInContext(expression, context),
  };
}

const summary = {
  generated_at: "2026-10-01T01:00:00Z",
  last_classified_at: "2026-10-01T00:59:00Z",
  last_observed_at: "2026-10-01T00:59:00Z",
  last_processed_at: "2026-10-01T00:59:00Z",
  stale_after_seconds: 300,
  model_name: "test-model",
  lifetime_flows: 123,
  lifetime_packets: 987654,
  total_events: 10,
  retained_packets: 20,
  retention_hours: 672,
  recent_window_minutes: 60,
  recent_counts: { BENIGN: 10, BOTNET: 0, BRUTE_FORCE: 0, DOS_DDOS: 0, OTHER_ATTACK: 0, UNVALIDATED: 0 },
  retained_counts: { BENIGN: 10, BOTNET: 0, BRUTE_FORCE: 0, DOS_DDOS: 0, OTHER_ATTACK: 0, UNVALIDATED: 0 },
  hourly: [{ bucket_start: "2026-10-01T01:00:00Z", counts: { BENIGN: 10, BOTNET: 0, BRUTE_FORCE: 0, DOS_DDOS: 0, OTHER_ATTACK: 0, UNVALIDATED: 0 } }],
  warnings: [],
};
const ok = (data = summary) => ({ ok: true, json: async () => data });

test("web probes render counts and tolerate a summary without them", async () => {
  const probes = { recent_requests: 21, recent_clients: 1, history_requests: 976, history_clients: 20, hourly: [] };
  const app = dashboard(async () => ok({ ...summary, web_probes: probes }));
  await settle();
  assert.equal(app.nodes.get("metric-probes").textContent, "976");
  assert.equal(app.nodes.get("metric-probes-detail").textContent, "from 20 clients");
  assert.match(app.nodes.get("chart-probes").innerHTML, /No web probe requests/);
  const old = dashboard(async () => ok());
  await settle();
  assert.equal(old.nodes.get("metric-probes").textContent, "—");
  assert.equal(old.nodes.get("metric-probes-detail").textContent, "Not reported");
  assert.match(old.nodes.get("chart-probes").innerHTML, /not reported/);
});
const settle = () => new Promise((resolve) => setImmediate(resolve));

test("lifetime traffic renders flows and labels the configured retention window", async () => {
  const app = dashboard(async () => ok());
  await settle();
  assert.equal(app.nodes.get("lifetime-flows").textContent, "123");
  assert.equal(app.nodes.get("label-totals-window").textContent, "last 28 days");
  assert.equal(app.nodes.get("retained-window").textContent, "last 28 days");
});

test("a failed refresh preserves the previous counter, totals, and chart", async () => {
  let fail = false;
  const app = dashboard(async () => {
    if (fail) throw new Error("network unavailable");
    return ok();
  });
  await settle();
  const chart = app.nodes.get("chart-flows");
  const previousRows = [...chart.children];
  fail = true;
  await app.refresh();
  assert.equal(app.nodes.get("lifetime-flows").textContent, "123");
  assert.equal(app.nodes.get("total-events").textContent, "10");
  assert.deepEqual(chart.children, previousRows);
  assert.match(app.nodes.get("activity-detail").textContent, /last successful update/);
  fail = false;
  await app.refresh();
  assert.equal(app.nodes.get("lifetime-flows").textContent, "123");
});

test("overlapping refreshes cannot render responses out of order", async () => {
  let complete;
  let calls = 0;
  const app = dashboard(() => {
    calls += 1;
    return new Promise((resolve) => { complete = resolve; });
  });
  await app.refresh();
  assert.equal(calls, 1);
  complete(ok());
  await settle();
  const nextRefresh = app.refresh();
  assert.equal(calls, 2);
  complete(ok({ ...summary, lifetime_flows: 124 }));
  await nextRefresh;
  assert.equal(app.nodes.get("lifetime-flows").textContent, "124");
});

test("an initial failure does not invent a lifetime total and can recover", async () => {
  let fail = true;
  const app = dashboard(async () => {
    if (fail) return { ok: false, status: 503 };
    return ok();
  });
  await settle();
  assert.equal(app.nodes.has("lifetime-flows"), false);
  assert.match(app.nodes.get("activity-detail").textContent, /Retrying automatically/);
  assert.equal(app.nodes.get("activity-badge").textContent, "Waiting for data");
  fail = false;
  await app.refresh();
  assert.equal(app.nodes.get("lifetime-flows").textContent, "123");
  assert.equal(app.nodes.get("activity-badge").textContent, "Live");
});

test("recent flow activity is live and uses the server clock despite browser clock skew", async () => {
  const app = dashboard(async () => ok());
  await settle();
  assert.equal(app.nodes.get("activity-badge").textContent, "Live");
  assert.match(app.nodes.get("activity-badge").className, /is-live/);
  assert.equal(app.nodes.get("activity-detail").textContent, "");
});

test("activity becomes stale exactly at the configured inactivity threshold", async () => {
  const app = dashboard(async () => ok({ ...summary, stale_after_seconds: 60 }));
  await settle();
  assert.equal(app.nodes.get("activity-badge").textContent, "Stale");
  assert.match(app.nodes.get("activity-badge").className, /is-stale/);
  assert.match(app.nodes.get("activity-detail").textContent, /last 1 minute\./);
});

test("an empty store waits for data, while expired history stays stale", async () => {
  const zeroCounts = { BENIGN: 0, BOTNET: 0, BRUTE_FORCE: 0, DOS_DDOS: 0, OTHER_ATTACK: 0, UNVALIDATED: 0 };
  let data = { ...summary, last_classified_at: null, last_observed_at: null, last_processed_at: null,
    lifetime_flows: 0, total_events: 0, retained_counts: zeroCounts, recent_counts: zeroCounts, hourly: [] };
  const app = dashboard(async () => ok(data));
  await settle();
  assert.equal(app.nodes.get("activity-badge").textContent, "Waiting for data");
  data = { ...data, lifetime_flows: 123 };
  await app.refresh();
  assert.equal(app.nodes.get("activity-badge").textContent, "Stale");
});

test("invalid summary data never replaces the last valid display", async () => {
  let data = summary;
  const app = dashboard(async () => ok(data));
  await settle();
  for (const invalid of [
    { ...summary, lifetime_flows: undefined },
    { ...summary, retained_counts: {} },
    { ...summary, total_events: 9 },
    { ...summary, lifetime_packets: -1 },
    { ...summary, last_observed_at: "invalid" },
    { ...summary, retained_counts: { ...summary.retained_counts, UNVALIDATED: undefined } },
    { ...summary, recent_counts: { ...summary.recent_counts, UNVALIDATED: -1 } },
  ]) {
    data = invalid;
    await app.refresh();
    assert.equal(app.nodes.get("lifetime-flows").textContent, "123");
    assert.equal(app.nodes.get("total-events").textContent, "10");
    assert.equal(app.nodes.get("activity-badge").textContent, "Stale");
  }
});

test("unvalidated flows have a separate counter, label row and hourly segment", async () => {
  const counts = { BENIGN: 0, BOTNET: 0, BRUTE_FORCE: 0, DOS_DDOS: 0, OTHER_ATTACK: 0, UNVALIDATED: 10 };
  const app = dashboard(async () => ok({ ...summary, retained_counts: counts, recent_counts: counts,
    hourly: [{ bucket_start: summary.generated_at, counts }] }));
  await settle();
  assert.equal(app.nodes.get("metric-unvalidated").textContent, "10");
  assert.equal(app.nodes.get("metric-attacks").textContent, "0");
  assert.equal(app.nodes.get("total-events").textContent, "10");
  const labels = app.nodes.get("label-list").children;
  assert.equal(labels.length, 6);
  assert.match(labels.at(-1).innerHTML, /is-unvalidated/);
  assert.equal(app.nodes.get("class-list").children.length, 6);
  const chart = app.nodes.get("chart-flows").children.at(-1).innerHTML;
  assert.match(chart, /is-unvalidated/);
  assert.doesNotMatch(chart, /is-dos/);
  assert.equal(app.nodes.get("activity-badge").textContent, "Live");
});

test("the unvalidated panel shows why flows are unvalidated", async () => {
  const counts = { BENIGN: 0, BOTNET: 0, BRUTE_FORCE: 0, DOS_DDOS: 0, OTHER_ATTACK: 0, UNVALIDATED: 10 };
  const reasons = { window_not_warm: 2, icmpv6_detection_not_validated: 1200, botnet_detection_not_validated: 3,
    new_reason: 1, v2_unavailable: 0 };
  const app = dashboard(async () => ok({ ...summary, retained_counts: counts, recent_counts: counts,
    hourly: [{ bucket_start: summary.generated_at, counts }], history_unvalidated_reasons: reasons }));
  await settle();
  const rows = app.nodes.get("reason-list").children.map((row) => [
    /class="nm"[^>]*>(.*?)</.exec(row.innerHTML)[1], /class="v[^"]*" title="(\S+) /.exec(row.innerHTML)[1]]);
  assert.deepEqual(rows, [["ICMPv6", (1200).toLocaleString()], ["Botnet predictions", "3"],
    ["Sensor warming up", "2"], ["New reason", "1"]]);
  for (const value of [{}, undefined, { icmpv6_detection_not_validated: -1 }, ["x"]]) {
    const other = dashboard(async () => ok({ ...summary, history_unvalidated_reasons: value }));
    await settle();
    assert.match(other.nodes.get("reason-list").innerHTML,
      value && !Array.isArray(value) && !Object.keys(value).length ? /No unvalidated flows/ : /No breakdown reported/);
    assert.equal(other.nodes.get("activity-badge").textContent, "Live");  // An odd breakdown never breaks the page.
  }
});

test("brute force has its own counter, label row and hourly segment", async () => {
  const counts = { BENIGN: 4, BOTNET: 0, BRUTE_FORCE: 3, DOS_DDOS: 0, OTHER_ATTACK: 0, UNVALIDATED: 0 };
  const app = dashboard(async () => ok({ ...summary, total_events: 7, retained_counts: counts,
    recent_counts: counts, hourly: [{ bucket_start: summary.generated_at, counts }],
    model_name: "nids-v6-tree-baseline-v2" }));
  await settle();
  assert.equal(app.nodes.get("metric-attacks").textContent, "3");
  assert.equal(app.nodes.get("model-name").textContent, "nids-v6-tree-baseline-v2");
  assert.ok(app.nodes.get("label-list").children.some((row) => /brute force/i.test(row.innerHTML)));
  assert.match(app.nodes.get("stat-attacks").className, /is-alert/);
  assert.equal(app.nodes.get("title-chart-attacks").textContent, "Suspected attacks per hour");
  assert.match(app.nodes.get("legend-attacks").innerHTML, /Brute force/);
  const chart = app.nodes.get("chart-attacks").children.at(-1).innerHTML;
  assert.match(chart, /is-brute/);
  assert.doesNotMatch(chart, /is-dos/);
});

test("a summary without the brute force label is rejected rather than rendered", async () => {
  const counts = { BENIGN: 10, BOTNET: 0, DOS_DDOS: 0, OTHER_ATTACK: 0, UNVALIDATED: 0 };
  const app = dashboard(async () => ok({ ...summary, retained_counts: counts, recent_counts: counts,
    hourly: [{ bucket_start: summary.generated_at, counts }] }));
  await settle();
  assert.notEqual(app.nodes.get("lifetime-flows")?.textContent, "123");
});

test("a stalled request times out, aborts and allows a later refresh", async () => {
  let timeout;
  let signal;
  let fail = true;
  const app = dashboard((url, options) => {
    signal = options.signal;
    return fail ? new Promise(() => {}) : Promise.resolve(ok());
  }, Date, { setTimeout(callback) { timeout = callback; }, clearTimeout() {} });
  timeout();
  await settle();
  assert.equal(signal.aborted, true);
  fail = false;
  await app.refresh();
  assert.equal(app.nodes.get("lifetime-flows").textContent, "123");
});

test("recent processing of an old flow does not claim live traffic", async () => {
  const app = dashboard(async () => ok({ ...summary, last_observed_at: "2026-09-30T00:00:00Z" }));
  await settle();
  assert.equal(app.nodes.get("activity-badge").textContent, "Stale");
});

test("a failed refresh marks activity stale and a successful refresh restores live", async () => {
  let fail = false;
  const app = dashboard(async () => {
    if (fail) throw new Error("network unavailable");
    return ok();
  });
  await settle();
  fail = true;
  await app.refresh();
  assert.equal(app.nodes.get("activity-badge").textContent, "Stale");
  assert.match(app.nodes.get("activity-detail").textContent, /Unable to confirm/);
  fail = false;
  await app.refresh();
  assert.equal(app.nodes.get("activity-badge").textContent, "Live");
});

test("activity ages into stale while a summary request is still pending", async () => {
  let now = 0;
  class Clock extends Date {
    static now() { return now; }
  }
  let calls = 0;
  let complete;
  const app = dashboard(() => {
    calls += 1;
    if (calls === 1) return Promise.resolve(ok());
    return new Promise((resolve) => { complete = resolve; });
  }, Clock);
  await settle();
  assert.equal(app.nodes.get("activity-badge").textContent, "Live");
  const pendingRefresh = app.refresh();
  now = 240000;
  await app.refresh();
  assert.equal(calls, 2);
  assert.equal(app.nodes.get("activity-badge").textContent, "Stale");
  complete(ok());
  await pendingRefresh;
});

test("the suspected attacks panel sums the attack classes and names each one", async () => {
  const counts = { BENIGN: 4, BOTNET: 0, BRUTE_FORCE: 3, DOS_DDOS: 2, OTHER_ATTACK: 0, UNVALIDATED: 1 };
  const app = dashboard(async () => ok({ ...summary, retained_counts: counts, recent_counts: counts,
    hourly: [{ bucket_start: summary.generated_at, counts }] }));
  await settle();
  assert.equal(app.nodes.get("metric-flows").textContent, "10");
  assert.equal(app.nodes.get("metric-attacks").textContent, "5");
  assert.equal(app.nodes.get("metric-attacks-detail").textContent, "Brute force 3 · DoS / DDoS 2");
  assert.match(app.nodes.get("stat-attacks").className, /is-alert/);
  const quiet = dashboard(async () => ok());
  await settle();
  assert.equal(quiet.nodes.get("metric-attacks").textContent, "0");
  assert.equal(quiet.nodes.get("metric-attacks-detail").textContent, "None predicted");
  assert.match(quiet.nodes.get("stat-attacks").className, /is-quiet/);
});

test("sensors and the model's service date render when reported, and are skipped when not", async () => {
  const app = dashboard(async () => ok({ ...summary,
    sensors: [{ source: "zeek-<worker>", last_observed_at: "2026-10-01T00:59:00Z", lag_seconds: 15, stale: false }],
    counter_provenance: "operational model changed: old -> test-model at 2026-09-20T07:17:18Z" }));
  await settle();
  const row = app.nodes.get("sensor-list").children[0].innerHTML;
  assert.match(row, /zeek-&lt;worker&gt;/);
  assert.match(row, /is-live/);
  assert.match(row, /15 s/);
  assert.equal(app.nodes.get("sensor-state").textContent, "Up");
  assert.equal(app.nodes.get("sensor-detail").textContent, "lag 15 s");
  assert.equal(app.nodes.get("model-since").hidden, false);
  assert.ok(app.nodes.get("model-since").textContent.includes("2026"));
  const bare = dashboard(async () => ok({ ...summary, sensors: "x", counter_provenance: "legacy totals" }));
  await settle();
  assert.match(bare.nodes.get("sensor-list").innerHTML, /not reported/);
  assert.equal(bare.nodes.get("model-since").hidden, true);
  assert.equal(bare.nodes.get("activity-badge").textContent, "Live");
});

/** A summary covering `hours` full hours plus the one in progress, 10 benign flows per hour. */
function longSummary(hours) {
  const end = Date.parse(summary.generated_at);
  const counts = summary.hourly[0].counts;
  return { ...summary, hourly: Array.from({ length: hours + 1 }, (_, i) => ({
    bucket_start: new Date(end - (hours - i) * 3600e3).toISOString(), counts })) };
}

test("picking a longer range asks the server for it and sums the charts into 6-hour buckets", async () => {
  const urls = [];
  const app = dashboard(async (url) => {
    urls.push(url);
    return ok(/hours=168/.test(url) ? longSummary(168) : summary);
  });
  await settle();
  assert.match(urls.at(-1), /hours=24$/);
  app.selectRange("7d");
  await settle();
  assert.match(urls.at(-1), /hours=168$/);
  assert.equal(app.nodes.get("range-label").textContent, "Last 7 days");
  assert.equal(app.nodes.get("title-flows").textContent, "Flows · 7d");
  assert.equal(app.nodes.get("title-chart-flows").textContent, "Flows per 6 hours");
  const times = app.get("charts['chart-flows'].times.length");
  assert.ok(times >= 28 && times <= 29, `${times} groups`);
  assert.equal(app.get("Math.max(...charts['chart-flows'].series[0].values)"), 60);
  assert.equal(app.nodes.get("metric-flows").textContent, "1.7K");
  // A week of history is only re-read every few minutes.
  const calls = urls.length;
  await app.tick();
  assert.equal(urls.length, calls);
});

test("a range picked while a request is out is loaded when it returns", async () => {
  const pending = [];
  const urls = [];
  const app = dashboard((url) => {
    urls.push(url);
    return new Promise((resolve) => pending.push(resolve));
  });
  app.selectRange("6h");
  assert.equal(urls.length, 1);
  pending.shift()(ok());
  await settle();
  await settle();
  assert.match(urls.at(-1), /hours=6$/);
  pending.shift()(ok(longSummary(6)));
  await settle();
  assert.equal(app.nodes.get("title-flows").textContent, "Flows · 6h");
  assert.equal(app.nodes.get("lifetime-flows").textContent, "123");
});

test("a range the server refuses falls back to the last 24 hours", async () => {
  const urls = [];
  const app = dashboard(async (url) => {
    urls.push(url);
    return /hours=168/.test(url) ? { ok: false, status: 422 } : ok();
  });
  await settle();
  app.selectRange("7d");
  await settle();
  await settle();
  assert.match(urls.at(-1), /hours=24$/);
  assert.equal(app.nodes.get("range-label").textContent, "Last 24 hours");
  assert.equal(app.nodes.get("activity-badge").textContent, "Live");
  app.selectRange("7d");
  await settle();
  assert.equal(urls.filter((url) => /hours=168/.test(url)).length, 1);
});
