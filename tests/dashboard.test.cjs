const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");

const script = fs.readFileSync(path.join(__dirname, "../app/static/app.js"), "utf8");

function dashboard(fetch) {
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
    Intl,
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
  model_name: "test-model",
  lifetime_flows: 123,
  lifetime_packets: 987654,
  total_events: 10,
  retention_hours: 672,
  recent_window_minutes: 60,
  recent_counts: {},
  all_time_counts: {},
  hourly: [{ bucket_start: "2026-10-01T01:00:00Z", counts: { BENIGN: 10 } }],
  warnings: [],
};
const ok = (data = summary) => ({ ok: true, json: async () => data });
const settle = () => new Promise((resolve) => setImmediate(resolve));

test("lifetime traffic renders flows and labels the configured retention window", async () => {
  const app = dashboard(async () => ok());
  await settle();
  assert.equal(app.nodes.get("lifetime-flows").textContent, "123");
  assert.equal(app.nodes.get("label-totals-window").textContent, "last 28 days");
  assert.equal(app.nodes.get("retained-flows-label").textContent, "Flows classified in the last 28 days");
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
  fail = false;
  await app.refresh();
  assert.equal(app.nodes.get("lifetime-flows").textContent, "123");
});
