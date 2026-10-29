# Feature contract v2 (draft)

Status: **offline extractor implemented; not wired into the exporter, API or
serving.** Drafted October 29, 2026. The extractor is `sensor/zeek_features_v2.py`.
Dataset preparation accepts `"feature_contract": "zeek-conn-window-v2"` in a
recipe (`tools/training_data.py`). The production
80-input contract (`zeek-conn-v1`: root `feature_order.json`, converter, scaler)
is unchanged and remains the controlled baseline. Nothing here changes the live
sensor, API, dashboard or deployed model.

## Why

An audit of `nids-v4` against the v1 converter found:

- **29 of 80 inputs are constant zero** for every row (all `*_std`, PSH/URG/CWE/ECE
  counts, bulk averages, initial window bytes, `idle_*`, `timestamp` after zeroing).
- About 22 more are exact copies of another input (min = max = mean packet length,
  subflow = total, active = duration). The standardized matrix has rank 26.
- `src_port` was the strongest single clue for *which public capture* a benign flow
  came from (69% balanced accuracy over six sources; chance 17%).
- Leave-one-source-out (LOSO) attack recall was ~0 for every held-out capture
  except CICIDS2017 Tuesday brute force. Benign false positives stayed below 1%.

A single conn.log record cannot describe brute force, scanning, botnet activity or
DoS well; those are defined by what a host does across many connections.

## Prototype evidence

Gradient-boosted trees (`HistGradientBoostingClassifier`, balanced weights),
LOSO over the six public capture groups, same reviewed labels as `nids-v4`:

| Held-out capture | v1 (80 inputs) | Per-connection v2 | Per-connection + window v2 |
| --- | ---: | ---: | ---: |
| CSE2018 DoS — DoS recall | 0.00 | 0.00 | **0.998** |
| CICIDS2017 Tue — brute-force recall | 0.60 | 0.60 | **0.82** (any attack 0.997) |
| CSE2018 SSH — brute-force recall | 0.00 | **0.98** | 0.002 (any attack 1.00) |
| IoT-23 Hakai — botnet recall | 0.00 | 0.00 | 0.00 |
| IoT-23 Mirai — DoS / botnet recall | 0.00 / 0.00 | 0.43 / 0.00 | 0.69 / 0.00 |
| CICIDS2017 Thu — brute force / other | 0.00 / 0.00 | 0.00 / 0.00 | 0.00 / 0.00 |
| Max held-out benign FP rate | 0.8% | 2.9% | 0.3% |

Trained on all public groups and applied to homelab traffic:

| Check | Per-connection v2 | + window v2 |
| --- | ---: | ---: |
| 38-case benign regression, false positives | 0 | **6** |
| Latest 30-min session, alerts/hour | 68 (mostly UDP 8472) | 38 (Kubernetes API/kubelet, VXLAN) |

Reading: explicit connection state and history fixed per-flow SSH brute force;
window features fixed DoS and most brute force across sources. Brute force and DoS
become confusable once repetition is visible, so the type head is less reliable
than the attack/benign decision. Botnet does not transfer between the two IoT-23
captures with either feature set. Homelab control-plane traffic (frequent
connections to one service) looks attack-like to a model that has never seen it,
so homelab benign **training** data is a prerequisite, not an extra.

These are prototype numbers on label-stratified samples, not deployment estimates.
The CICIDS2017 inputs are host-filtered subsets, which distorts their windows.

### Implementation check (same LOSO, implemented extractor)

Applying the same reviewed labels as `nids-v4` with the implemented extractor kept
63,282 of 63,313 rows. 31 were excluded as cold windows, and every reviewed
record matched its pinned conn.log exactly. Gradient-boosted trees, LOSO:

| Held-out capture | v1 any-attack | Prototype any-attack | Implemented any-attack |
| --- | ---: | ---: | ---: |
| CICIDS2017 Tue | 0.61 | 0.997 | 0.75 |
| CSE2018 SSH brute force | 0.00 | 1.00 | 1.00 |
| CSE2018 DoS | 0.08 | 0.999 | 0.385 (DoS recall 0) |
| IoT-23 Mirai | 0.39 | 0.16 | **0.85** (DoS recall 0.81; benign FP 2.8%) |
| IoT-23 Hakai, CICIDS2017 Thu | ~0 | ~0 | ~0 |

Removing the inputs added after the prototype changed nothing, so the shifts come
from the watermark window rule. The CSE DoS rows have strong window signals
(median 1,196 failed connections to one service per minute). In that fold,
though, the only other DoS training data is 235 Mirai rows, so the result is
fragile under either rule. Treat single-source folds as unreliable until each
class has at least two independent sources.

## Contract identity and versioning

- Contract ID `zeek-conn-window-v2`, recorded in the model bundle as
  `feature_contract.json`: ID, ordered names, window length, the converter source
  hash and a schema version. Inference refuses a bundle whose contract does not
  match the converter it is paired with.
- Feature names that keep v1 semantics keep v1 names (`dst_port`, `protocol`,
  `tot_fwd_pkts`, `tot_bwd_pkts`, `flow_duration`). `validate_features` and
  packet-count storage depend on `tot_fwd_pkts`/`tot_bwd_pkts`.
- No `timestamp`, `src_port`, `idle_*`, or other always-zero input. No IP
  addresses, `local_orig`/`local_resp`, or Zeek `service` as model inputs: they
  encode the site rather than the behavior.

## Per-connection inputs (from one conn.log record)

| Group | Inputs |
| --- | --- |
| Identity | `dst_port`, `protocol` (numeric `ip_proto` precedence, as in v1) |
| Volume | `flow_duration` (µs), `tot_fwd_pkts`, `tot_bwd_pkts`, `fwd_ip_bytes`, `bwd_ip_bytes`, `fwd_payload_bytes`, `bwd_payload_bytes`, `fwd_header_bytes`, `bwd_header_bytes` |
| Ratios | `bytes_per_s`, `bwd_fwd_pkt_ratio`, `fwd_mean_pkt_bytes`, `bwd_mean_pkt_bytes`, `missed_bytes` |
| State | one-hot `conn_state_*` over Zeek's 13 states (`S0`, `S1`, `SF`, `REJ`, `S2`, `S3`, `RSTO`, `RSTR`, `RSTOS0`, `RSTRH`, `SH`, `SHR`, `OTH`) |
| History | per-letter counts of Zeek `history`, kept separate by direction: originator `S H A D F R C G T W I Q ^`, responder `s h a d f r c g t w i q`. Replaces v1's direction-merged `syn/fin/rst/ack` counts. |

Most history letters are recorded at most once per direction, so these inputs
are mainly presence flags. Repeated-event letters (checksum `C`, retransmission
`T`, zero window `W`, and `G` gaps) are logged on a logarithmic scale (1st, 10th,
100th…), so their counts are buckets, not packet counts. Because `-C` disables
checksum verification in production, `C`/`c` will normally be absent. The
prototype used a subset of these letters, and `missed_bytes` was added after
the prototype run.

## Window inputs (per sensor, causal)

Semantics, chosen so offline extraction reproduces online inference exactly:

- **Order**: conn.log write order. The exporter already reads in this order;
  offline preparation must iterate the full conn.log in file order too.
- **Time**: a record's end time `ts + duration`. The clock is a watermark: the
  largest end time written so far. A record sees every previously written record
  whose end time is within 60 seconds of the watermark, plus itself exactly once.
  It never sees later-written records. A record logged after it already fell out
  of the window still sees the current window and counts itself, but is not
  retained. Aggregates are exact: per-key min-heaps on end time.
- **Warm-up**: `window_warm` is true once the watermark is 60 seconds past the
  first record. Dataset preparation excludes cold, degraded and tunnel-carrier
  rows and counts them per source in the manifest.
- **Scope**: one sensor's log. Each DaemonSet sensor keeps its own state; no
  cross-node join.

| Key | Inputs over the window |
| --- | --- |
| Originator host | `src_conns`, `src_distinct_dst_hosts`, `src_distinct_dst_ports`, `src_same_service_conns` (same responder host+port), `src_failed_frac` (`S0`, `REJ`, `RSTOS0`, `RSTRH`, `SH*`, `OTH`; `RSTO`/`RSTR` only when one side sent no payload), `src_mean_bwd_payload` |
| Responder host | `dst_conns`, `dst_distinct_src_hosts`, `dst_failed_frac` |
| Responder service (host+port) | `svc_distinct_src_hosts` |

Candidates for a later version, only with LOSO evidence: a 5-second window for
burst floods, a 300-second window for slow scans, and per-/24 originator
aggregation for distributed sources.

### Exporter state

- Bounded per-key deques, evicted by end time; a hard cap on tracked keys with
  oldest-first eviction. When the cap or eviction fires, emit a
  `window_degraded` marker rather than silently producing low counts.
- After a restart, state starts empty. Flows in the first 60 seconds are marked
  `window_warm=false`. The server stores their prediction but reports
  `UNVALIDATED` with reason `window_not_warm`, as already done for ICMPv6.
- Checkpointing window state is not required for v2.

## Tunnels (depends on the VXLAN 8472 fix)

- Inner pod connections are classified normally.
- Outer UDP 8472 (and 4789) connections are not sent for inference. They are
  counted as tunnel carriers for packet totals, so encapsulated packets are not
  counted twice.
- Outer and inner flows have separate window state: an inner pod flow does not
  update the node-to-node outer keys, and the reverse.

## Training pipeline changes

- A dataset recipe source points at the **complete** conn.log (hash-pinned)
  alongside the reviewed labels. Window inputs are computed over every record in
  that log **before** per-label sampling; sampling selects rows, never shrinks
  the window context.
- Unreviewed records stay window context only; they never become training rows.
- `training_data.py` gets a contract parameter. v1 preparation stays
  byte-for-byte reproducible.
- Splits stay whole-capture. Add LOSO as a standard report next to the fixed
  validation split.

## Serving and API changes

Implemented locally; nothing is deployed.

- **Ingest schema** (`app/schemas.py`): each `FlowRecord` may carry
  `features_v2`, `window_warm` and `window_degraded`, always together. A batch
  that carries them must name `features_v2_contract`. `features` stays the v1
  object, and the v1 payload hash (deduplication) ignores the v2 fields, so
  replays with or without them stay duplicates.
- **Shadow model** (`app/shadow.py`): loads only when `NIDS_SHADOW_MODEL_DIR` is
  set. `NIDS_SHADOW_MODEL_SHA256` must match `tree_model.joblib` before the
  pickle is opened. The bundle must declare this contract. Flows are reported
  `unvalidated` with reason `window_degraded`, `window_not_warm` or the existing
  ICMPv6 reason.
- **Storage** (`shadow_predictions` table): keyed by source, flow and model ID,
  together with the production summary label for agreement analysis, and
  purged on the same retention schedule. Public summaries, counters and the
  dashboard never read it. The token-protected `GET /api/internal/shadow/summary`
  reports, per model, the shadow counts, unvalidated reasons, a production-vs-shadow
  agreement matrix and alert totals.
- **Failure isolation**: shadow classification runs after the operational batch
  commits, and any error is logged and skipped. A configured but unavailable
  shadow model adds a `/healthz` warning without degrading status.
- **Exporter** (`--features-v2` or `NIDS_EXPORT_FEATURES_V2=1`): one window state
  per process. Every valid conn.log line goes through it once, in log order,
  even if v1 rejects the line. A line re-read after a failed export goes out
  without v2 rather than being counted twice. VXLAN carriers stay v1-only. If the
  server rejects the v2 fields with 422, the batch is resent without them, so
  v1 flows are never quarantined because of shadow data.
- The dashboard needs `BRUTE_FORCE` before any five-class promotion.

### Shadow rollout (for the operator, through GitOps)

1. Deploy the application image with this code and **no** shadow variables.
   Behavior is unchanged; startup creates the empty shadow table. Confirm the
   summary, ingest and `/readyz` as usual.
2. Make the candidate bundle available to the API pod read-only. That means
   `tree_model.joblib`, `feature_order.json`, `label_map.json` and
   `feature_contract.json`. At 1.7 MB the model exceeds the ConfigMap/Secret size
   limit, so use a volume (for example a PVC, or an init container from a private
   image). It was trained on private homelab traffic; do not bake it into a
   public image.
3. Set `NIDS_SHADOW_MODEL_DIR` to that path and `NIDS_SHADOW_MODEL_SHA256` to the
   model file's hash. Confirm that `/healthz` has no shadow warning and that
   `/api/internal/shadow/summary` reports `shadow_available: true`.
4. Only then set `NIDS_EXPORT_FEATURES_V2=1` on the Zeek exporter. Expect the
   first minute after each exporter restart to be `window_not_warm`.
5. Run for at least a week. Review the agreement matrix and every alert source
   the shadow model raises. Rollback is unsetting the variables; shadow rows
   expire with retention.

## Promotion gates (proposal)

A v2 candidate may replace v1 only if, on a final test set reserved before model
selection:

1. Benign false alerts per hour on fresh homelab sessions are at or below v1,
   and the 38-case regression false positives are at or below v1's 3.
2. LOSO attack-vs-benign recall beats v1 on at least four of six public groups,
   with no group's benign false positive rate above 1%.
3. Per-class precision and recall are reported. A class is promoted for typed
   output only if its held-out recall is meaningful (target ≥ 0.5). Otherwise it
   is reported as a generic attack.
4. Shadow mode on live traffic for at least one week shows no unexplained alert
   source.

## Open questions

- Two-stage output (attack vs. benign, then type) versus one five-class model.
  The prototype's brute-force/DoS confusion favors two stages.
- How IoT-23 "botnet" labels map: C&C, scanning and DDoS sub-labels may need to
  become their own behavioral classes before botnet is learnable.
- Window length under Zeek's connection timeouts. Long-lived connections are
  logged late; their windows reflect logging time, not start time.
- Whether a per-site allowlist (Kubernetes API, kubelet, VXLAN, resolver) belongs
  in the model, in post-filtering, or only in training data.

Prototype scripts are not committed. They live in the private session scratchpad
and are reproducible from the description above.
