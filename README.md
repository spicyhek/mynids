# mynids

This is a Network Intrusion Detection System made for my homelab cluster. It's trained on the CICIDS2018 dataset using a multi-layer perceptron across 9 million rows and 4 classes, getting a validation accuracy of 97% and an averaged f1-score of 0.98.

The service has two surfaces:

- Public:
  - `GET /`
  - `GET /api/public/summary`
  - `GET /healthz` (liveness)
  - `GET /readyz` (returns 503 when ingestion is not ready)
- Private:
  - `POST /api/internal/flows`
  - `GET /api/internal/events` (requires `X-Ingest-Token`)

The site intentionally exposes only aggregate statistics.

## ICMPv6 validation status

New flows with model feature `protocol: 58` are recorded as `unvalidated`, with
reason `icmpv6_detection_not_validated`. Their raw model label and score are
preserved. The operational `UNVALIDATED` category is separate from the four model
classes: it is not a benign verdict, an attack verdict, or a fifth trained class.
Other protocols retain status `classified`, which describes a model prediction,
not an independently confirmed incident or an accuracy guarantee.

## Ingestion contract and delivery guarantees

`POST /api/internal/flows` requires `X-Ingest-Token` and a body containing a
nonempty `source` and 1–1000 `flows` (maximum body size: 8 MiB). Each flow requires:

- `flow_id`: a stable identifier, unique within the source (maximum 200 characters).
- `event_time`: an ISO-8601 timestamp with timezone; dates before 1970 or more than
  five minutes ahead of the server are rejected.
- `features`: the complete numeric feature object in the feature mapping below.
  Packet counts must be nonnegative integers, ports must be 0–65535, and
  protocol numbers must be 0–255. Missing, extra, nonfinite, and overflowing
  model features are rejected rather than silently replaced.

Malformed records and individual HTTP 409/413/422 rejections go into
`<state-file>.quarantine.jsonl`; batches are split to isolate rejected records.
The journal rotates at approximately 1 MiB and keeps one previous file. Each
entry includes the reason, hash and up to 64 KiB of the rejected record for
investigation. Quarantined records are not counted as acknowledged flows.
Preserve source logs for longer-term recovery; this bounded journal is not an archive.
Pending batch files must not be deleted to bypass a delivery error.

## Counter and time semantics

- `lifetime_flows` counts newly committed source/flow identities.
- `lifetime_packets` sums originator and responder packets represented by those
  flows. It is not a separate measurement of all packets on the network.
- `total_events` and `retained_counts` describe retained event rows.
  `all_time_counts` is a deprecated alias for `retained_counts`.
- `retained_packets` sums known packet counts on retained rows.
  `packet_counts_complete` is false when legacy rows have unknown packet counts.
- Recent and hourly windows use observation time with inclusive lower and upper
  bounds; future events are excluded. Hourly output includes empty buckets and
  partial first/current hours for the requested rolling window.
- `last_observed_at` is the most recent flow start time.
  `last_processed_at` is the last time a new classification was committed;
  `last_classified_at` is its compatibility alias. These survive event purges.
- `sensors` reports last delivery, latest observation, observation lag, and
  delivery staleness. Quiet traffic and an offline sensor cannot be distinguished
  without independent sensor heartbeats. The dashboard's activity badge uses
  observation time so an old replay does not look like current traffic.

Summary queries share one SQLite read snapshot. Retained totals are updated
transactionally on insertion and deletion; existing databases are backfilled once
on upgrade. Retention runs at startup and periodically, outside the public request
path. Each maintenance pass deletes at most 1,000 expired rows, so retained
totals can temporarily include rows awaiting cleanup. The dashboard validates
a complete summary before updating its counters and aborts stalled requests
after ten seconds.

## Upgrading an existing installation

1. Pause exporters and back up the database, source logs, checkpoints, and pending files.
2. Deploy the server and exporter changes together, preserving existing source
   names and checkpoint locations. Old exporters lack the required flow ID;
   new exporters require the new acknowledgment fields.
3. Resume exporters and check `/readyz`, the summary's `sensors`, and quarantine logs.
4. Reconcile `sum(retained_counts.values()) == total_events` and replay a test
   batch to confirm the second acknowledgment reports duplicates.

Schema changes are additive and legacy counters are preserved. Historical
duplicates cannot be removed reliably because old rows have no flow IDs.
Historical per-flow packet counts cannot be recovered from a batch total.
`counter_provenance` identifies preserved legacy totals. Replaying pre-upgrade
traffic can therefore count it again once; deduplication begins with the new IDs.
Back up before downgrade: older code does not maintain the new deduplication ledger.

`/healthz` is liveness/status; `/readyz` additionally checks storage and returns
503 when the model is unavailable/degraded or the ingestion token is missing.
PR checks run the regression suites and actual model smoke test. Container builds
also execute the smoke test for each target architecture before publication.
Direct dependencies are pinned; TensorFlow/Keras/scikit-learn versions match
the saved model and estimator metadata. Transitive dependencies are not fully locked.

## Model verification

Run the runtime and regression checks in the project's Python environment:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
node --test tests/dashboard.test.cjs
.\.venv\Scripts\python.exe -m tools.smoke_model
```

For labeled JSONL with `label`, `source`, and either `conn` or `flow`, use
`python -m tools.evaluate_replay dataset.jsonl --output report.json`.

`tools.verify_model` also accepts the reviewed CICIDS2018 CSVs from the
`primus11/cic-ids-2018-dataset` and `solarmainframe/ids-intrusion-csv` Kaggle datasets:

```powershell
.\.venv\Scripts\python.exe -m tools.verify_model --csv data/evaluation/cic.csv data/evaluation/solarmainframe/02-15-2018.csv data/evaluation/solarmainframe/02-21-2018.csv data/evaluation/solarmainframe/03-02-2018.csv --output-dir data/evaluation/all-classes
```

## Zeek feature conversion

Protocol conversion prefers Zeek's numeric `ip_proto` field. Zeek can report
`proto: "icmp"` for both IPv4 ICMP (`ip_proto: 1`) and ICMPv6 (`ip_proto: 58`).
For older records without `ip_proto`, ICMP endpoint addresses determine the IP
version; the legacy IPv4 fallback applies when neither address is present.
Invalid or contradictory protocol metadata is quarantined by the exporter.
Correct protocol mapping does not by itself resolve the model's observed
false positives on IPv6 control traffic.

All 80 features in `feature_order.json` are required for each flow. Since all 80 features are not possible to see directly with Zeek, some calculations and approximations are made:

- `direct`: copied directly from Zeek with light normalization
- `derived`: computed from one or more Zeek fields
- `approx`: filled using a documented approximation because Zeek `conn.log` does not expose the exact CICIDS source signal
- `zero`: unavailable from Zeek `conn.log`, `0.0` for now

| CICIDS feature      | Zeek source                    | strategy | notes                                                       |
| ------------------- | ------------------------------ | -------- | ----------------------------------------------------------- |
| `dst_port`          | `id.resp_p`                    | direct   | responder port                                              |
| `protocol`          | `ip_proto`, `proto`, endpoints | derived  | actual IP protocol; distinguishes ICMPv6 (58) from ICMP (1) |
| `timestamp`         | `ts`                           | derived  | epoch microseconds on the wire; zeroed before model scaling |
| `flow_duration`     | `duration`                     | derived  | seconds converted to microseconds                           |
| `tot_fwd_pkts`      | `orig_pkts`                    | direct   | originator packet count                                     |
| `tot_bwd_pkts`      | `resp_pkts`                    | direct   | responder packet count                                      |
| `totlen_fwd_pkts`   | `orig_ip_bytes`                | direct   | falls back to `orig_bytes`                                  |
| `totlen_bwd_pkts`   | `resp_ip_bytes`                | direct   | falls back to `resp_bytes`                                  |
| `fwd_pkt_len_max`   | `orig_ip_bytes`, `orig_pkts`   | approx   | uses forward mean packet length                             |
| `fwd_pkt_len_min`   | `orig_ip_bytes`, `orig_pkts`   | approx   | uses forward mean packet length                             |
| `fwd_pkt_len_mean`  | `orig_ip_bytes`, `orig_pkts`   | derived  | bytes per packet                                            |
| `fwd_pkt_len_std`   | unavailable                    | zero     | Zeek `conn.log` lacks packet-level variance                 |
| `bwd_pkt_len_max`   | `resp_ip_bytes`, `resp_pkts`   | approx   | uses backward mean packet length                            |
| `bwd_pkt_len_min`   | `resp_ip_bytes`, `resp_pkts`   | approx   | uses backward mean packet length                            |
| `bwd_pkt_len_mean`  | `resp_ip_bytes`, `resp_pkts`   | derived  | bytes per packet                                            |
| `bwd_pkt_len_std`   | unavailable                    | zero     | Zeek `conn.log` lacks packet-level variance                 |
| `flow_byts_s`       | totals, `duration`             | derived  | total IP bytes divided by duration                          |
| `flow_pkts_s`       | totals, `duration`             | derived  | total packets divided by duration                           |
| `flow_iat_mean`     | `duration`, total packets      | approx   | average total flow inter-arrival time                       |
| `flow_iat_std`      | unavailable                    | zero     | no packet timeline in `conn.log`                            |
| `flow_iat_max`      | `duration`, total packets      | approx   | set to average IAT                                          |
| `flow_iat_min`      | `duration`, total packets      | approx   | set to average IAT                                          |
| `fwd_iat_tot`       | `duration`, `orig_pkts`        | approx   | total forward IAT span                                      |
| `fwd_iat_mean`      | `duration`, `orig_pkts`        | approx   | average forward IAT                                         |
| `fwd_iat_std`       | unavailable                    | zero     | no packet timeline in `conn.log`                            |
| `fwd_iat_max`       | `duration`, `orig_pkts`        | approx   | set to average forward IAT                                  |
| `fwd_iat_min`       | `duration`, `orig_pkts`        | approx   | set to average forward IAT                                  |
| `bwd_iat_tot`       | `duration`, `resp_pkts`        | approx   | total backward IAT span                                     |
| `bwd_iat_mean`      | `duration`, `resp_pkts`        | approx   | average backward IAT                                        |
| `bwd_iat_std`       | unavailable                    | zero     | no packet timeline in `conn.log`                            |
| `bwd_iat_max`       | `duration`, `resp_pkts`        | approx   | set to average backward IAT                                 |
| `bwd_iat_min`       | `duration`, `resp_pkts`        | approx   | set to average backward IAT                                 |
| `fwd_psh_flags`     | unavailable                    | zero     | TCP PSH/URG counts are not provided by conn.log history     |
| `bwd_psh_flags`     | unavailable                    | zero     | TCP PSH/URG counts are not provided by conn.log history     |
| `fwd_urg_flags`     | unavailable                    | zero     | TCP PSH/URG counts are not provided by conn.log history     |
| `bwd_urg_flags`     | unavailable                    | zero     | TCP PSH/URG counts are not provided by conn.log history     |
| `fwd_header_len`    | `orig_ip_bytes`, `orig_bytes`  | derived  | IP bytes minus payload bytes                                |
| `bwd_header_len`    | `resp_ip_bytes`, `resp_bytes`  | derived  | IP bytes minus payload bytes                                |
| `fwd_pkts_s`        | `orig_pkts`, `duration`        | derived  | forward packets per second                                  |
| `bwd_pkts_s`        | `resp_pkts`, `duration`        | derived  | backward packets per second                                 |
| `pkt_len_min`       | directional packet means       | approx   | minimum of available directional means                      |
| `pkt_len_max`       | directional packet means       | approx   | maximum of available directional means                      |
| `pkt_len_mean`      | total bytes, total packets     | derived  | aggregate mean packet length                                |
| `pkt_len_std`       | unavailable                    | zero     | no packet-level variance in `conn.log`                      |
| `pkt_len_var`       | unavailable                    | zero     | no packet-level variance in `conn.log`                      |
| `fin_flag_cnt`      | `history`                      | approx   | count of `F` and `f`                                        |
| `syn_flag_cnt`      | `history`                      | approx   | counts `S`, `s`, `H`, `h`                                   |
| `rst_flag_cnt`      | `history`                      | approx   | count of `R` and `r`                                        |
| `psh_flag_cnt`      | unavailable                    | zero     | TCP PSH/URG counts are not provided by conn.log history     |
| `ack_flag_cnt`      | `history`                      | approx   | count of `A` and `a`                                        |
| `urg_flag_cnt`      | unavailable                    | zero     | TCP PSH/URG counts are not provided by conn.log history     |
| `cwe_flag_count`    | unavailable                    | zero     | not exposed by `conn.log`                                   |
| `ece_flag_cnt`      | unavailable                    | zero     | not exposed by `conn.log`                                   |
| `down_up_ratio`     | `resp_pkts`, `orig_pkts`       | derived  | backward packets divided by forward packets                 |
| `pkt_size_avg`      | total bytes, total packets     | derived  | same value as `pkt_len_mean`                                |
| `fwd_seg_size_avg`  | forward bytes, `orig_pkts`     | derived  | same value as `fwd_pkt_len_mean`                            |
| `bwd_seg_size_avg`  | backward bytes, `resp_pkts`    | derived  | same value as `bwd_pkt_len_mean`                            |
| `fwd_byts_b_avg`    | unavailable                    | zero     | Zeek `conn.log` has no bulk-window metric                   |
| `fwd_pkts_b_avg`    | unavailable                    | zero     | Zeek `conn.log` has no bulk-window metric                   |
| `fwd_blk_rate_avg`  | unavailable                    | zero     | Zeek `conn.log` has no bulk-window metric                   |
| `bwd_byts_b_avg`    | unavailable                    | zero     | Zeek `conn.log` has no bulk-window metric                   |
| `bwd_pkts_b_avg`    | unavailable                    | zero     | Zeek `conn.log` has no bulk-window metric                   |
| `bwd_blk_rate_avg`  | unavailable                    | zero     | Zeek `conn.log` has no bulk-window metric                   |
| `subflow_fwd_pkts`  | `orig_pkts`                    | approx   | single Zeek record treated as one subflow                   |
| `subflow_fwd_byts`  | `orig_ip_bytes`                | approx   | single Zeek record treated as one subflow                   |
| `subflow_bwd_pkts`  | `resp_pkts`                    | approx   | single Zeek record treated as one subflow                   |
| `subflow_bwd_byts`  | `resp_ip_bytes`                | approx   | single Zeek record treated as one subflow                   |
| `init_fwd_win_byts` | unavailable                    | zero     | TCP window size not exposed in `conn.log`                   |
| `init_bwd_win_byts` | unavailable                    | zero     | TCP window size not exposed in `conn.log`                   |
| `fwd_act_data_pkts` | `orig_pkts`                    | approx   | uses forward packet count                                   |
| `fwd_seg_size_min`  | forward bytes, `orig_pkts`     | approx   | uses forward mean packet length                             |
| `active_mean`       | `duration`                     | approx   | single active period treated as entire duration             |
| `active_std`        | unavailable                    | zero     | no multi-burst timeline in `conn.log`                       |
| `active_max`        | `duration`                     | approx   | same as active mean                                         |
| `active_min`        | `duration`                     | approx   | same as active mean                                         |
| `idle_mean`         | unavailable                    | zero     | no idle burst segmentation in `conn.log`                    |
| `idle_std`          | unavailable                    | zero     | no idle burst segmentation in `conn.log`                    |
| `idle_max`          | unavailable                    | zero     | no idle burst segmentation in `conn.log`                    |
| `idle_min`          | unavailable                    | zero     | no idle burst segmentation in `conn.log`                    |
| `src_port`          | `id.orig_p`                    | direct   | originator port                                             |
