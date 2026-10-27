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
  return { context, nodes, refresh: () => vm.runInContext("refresh()", context) };
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
  recent_counts: { BENIGN: 10, BOTNET: 0, DOS_DDOS: 0, OTHER_ATTACK: 0, UNVALIDATED: 0 },
  retained_counts: { BENIGN: 10, BOTNET: 0, DOS_DDOS: 0, OTHER_ATTACK: 0, UNVALIDATED: 0 },
  hourly: [{ bucket_start: "2026-10-01T01:00:00Z", counts: { BENIGN: 10, BOTNET: 0, DOS_DDOS: 0, OTHER_ATTACK: 0, UNVALIDATED: 0 } }],
  warnings: [],
};
const ok = (data = summary) => ({ ok: true, json: async () => data });
const settle = () => new Promise((resolve) => setImmediate(resolve));

test("lifetime traffic renders flows and labels the configured retention window", async () => {
  const app = dashboard(async () => ok());
  await settle();
  assert.equal(app.nodes.get("lifetime-flows").textContent, "123");
  assert.equal(app.nodes.get("label-totals-window").textContent, "last 28 days");
  assert.equal(app.nodes.get("retained-flows-label").textContent, "Flows observed in the last 28 days");
});

test("a failed refresh preserves the previous counter, totals, and chart", async () => {
  let fail = false;
  const app = dashboard(async () => {
    if (fail) throw new Error("network unavailable");
    return ok();
  });
  await settle();
  const chart = app.nodes.get("hourly-chart");
  const previousRows = [...chart.children];
  fail = true;
  await app.refresh();
  assert.equal(app.nodes.get("lifetime-flows").textContent, "123");
  assert.equal(app.nodes.get("total-events").textContent, "10");
  assert.deepEqual(chart.children, previousRows);
  assert.match(app.nodes.get("warning-list").children.at(-1).textContent, /last successful update/);
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
  assert.match(app.nodes.get("warning-list").children.at(-1).textContent, /Retrying automatically/);
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
  assert.match(app.nodes.get("activity-detail").textContent, /5 minutes/);
});

test("activity becomes stale exactly at the configured inactivity threshold", async () => {
  const app = dashboard(async () => ok({ ...summary, stale_after_seconds: 60 }));
  await settle();
  assert.equal(app.nodes.get("activity-badge").textContent, "Stale");
  assert.match(app.nodes.get("activity-badge").className, /is-stale/);
  assert.match(app.nodes.get("activity-detail").textContent, /last 1 minute\./);
});

test("an empty store waits for data, while expired history stays stale", async () => {
  const zeroCounts = { BENIGN: 0, BOTNET: 0, DOS_DDOS: 0, OTHER_ATTACK: 0, UNVALIDATED: 0 };
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

test("unvalidated ICMPv6 has a separate counter, label row and hourly segment", async () => {
  const counts = { BENIGN: 0, BOTNET: 0, DOS_DDOS: 0, OTHER_ATTACK: 0, UNVALIDATED: 10 };
  const app = dashboard(async () => ok({ ...summary, retained_counts: counts, recent_counts: counts,
    hourly: [{ bucket_start: summary.generated_at, counts }] }));
  await settle();
  assert.equal(app.nodes.get("recent-unvalidated").textContent, "10");
  assert.equal(app.nodes.get("recent-benign").textContent, "0");
  assert.equal(app.nodes.get("recent-dos").textContent, "0");
  assert.equal(app.nodes.get("total-events").textContent, "10");
  const labels = app.nodes.get("label-list").children;
  assert.equal(labels.length, 5);
  assert.match(labels.at(-1).innerHTML, /unvalidated ICMPv6/);
  const chart = app.nodes.get("hourly-chart").children[0].innerHTML;
  assert.match(chart, /is-unvalidated/);
  assert.doesNotMatch(chart, /is-dos/);
  assert.equal(app.nodes.get("activity-badge").textContent, "Live");
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
