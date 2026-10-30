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

## Retraining baseline and dataset preparation

For new homelab collection, use the standalone `tools/capture_session.py` and
follow `training/CAPTURE_GUIDE.md`. It pairs full-packet Linux capture with UTC
activity markers, command outcomes, capture-quality checks and a sealed hash
manifest. Activities remain unreviewed until matched to protocol evidence.

The offline retraining tools keep the existing input shape `(N, 80)`. The default
class map has four outputs; `training/labels.five-class.json` defines a separate
five-output candidate with `BRUTE_FORCE` distinct from `OTHER_ATTACK`. The root
production model and its four-class map remain unchanged. Training uses the production Zeek converter for every source;
original CICFlowMeter feature CSVs are not accepted by this preparation path.
Observation times remain in metadata, while the model timestamp column is set
to zero before fitting the new scaler and during inference.

Keep private captures, label evidence, prepared datasets, and candidate model
bundles under gitignored `data/`. Commit reusable tools, reviewed configuration
templates, synthetic fixtures, and sanitized aggregate results. Real captures,
endpoint details, and operational notes require a separate private backup.
`CONVERSATION_CONTEXT.md` is also ignored because it contains operational details.

### Reviewed source recipes

Copy `training/dataset.example.json` into a private working recipe and replace
the example paths and SHA-256 values. Paths resolve relative to that recipe.
Each source entry requires:

- `path` and `sha256`: reviewed JSONL rows containing `source`, a real class
  `label`, and a Zeek `conn` record, as accepted by the offline evaluator.
- `provenance_path`, `provenance_sha256`, and `label_basis`: independently
  reviewed label evidence. Hashes pin the reviewed input; they do not certify
  label quality by themselves.
- `origin`: the source dataset or collection environment, for auditing whether
  a class is confounded with its source. Include reviewed benign examples from
  public sources as well as attacks and homelab workloads.
- `group`: the complete capture/session grouping boundary. Related captures
  from one campaign may need the same group even when stored in separate files.
- `split`: explicitly `train`, `validation`, `test`, or `regression`.

A top-level `label_map` object may specify a separate candidate map by `path` and
`sha256`; paths resolve relative to the recipe. Indices must be contiguous and
follow LabelEncoder's alphabetic order. Keeping the candidate specification
separate avoids changing the class map expected by the deployed four-output model.
Optional source fields `max_records_per_label` and `sample_seed` apply reproducible
reservoir sampling within an already assigned capture split. Every input row is
still validated and checked for duplicate identities before sampling; manifests
record full source counts and sampling parameters.

Keep whole related sessions in one split. Preparation rejects group overlap,
duplicate flow IDs even under different source aliases, unknown labels,
invalid features, changed source/evidence hashes, and precomputed feature rows.
It never silently discards invalid observations or assigns labels from model
predictions. `UNVALIDATED` is an operational status, not a training truth label.

```powershell
.\.venv\Scripts\python.exe -m tools.prepare_training_dataset `
  data/datasets/reviewed.recipe.json --output data/datasets/nids-v1-prepared
```

The new output contains canonical `records.jsonl`, per-split JSONL files,
the recipe snapshot, and a manifest with class/group counts, source hashes,
feature order, and converter/validation/inference code hashes. Existing output
directories are never overwritten. Reprepare a new version after changing the
feature contract or its preprocessing code.

The current private seed, `data/datasets/nids-v1-seed`, contains 38 reviewed
benign homelab flows assigned to `regression`. It is intentionally marked
`ready_for_four_class_training: false`. Previously inspected captures are useful
regression cases and must not be relabeled as an untouched final test.

### Public raw attack captures

[CSE-CIC-IDS2018](https://www.unb.ca/cic/datasets/ids-2018.html) provides raw
captures and scenario descriptions. Its daily PCAP ZIPs are tens of gigabytes.
`tools.cicids_archives` uses anonymous AWS CLI reads to inspect a 1 MiB ZIP tail
and fetch only a selected member with S3 byte ranges. It verifies the archive
ETag, range lengths, decompressed length, and CRC, then records the capture hash
and source provenance. Download/extraction budgets are explicit; archive member
names never determine output filesystem paths. AWS CLI must be installed.

```powershell
.\.venv\Scripts\python.exe -m tools.cicids_archives catalog `
  --day Thursday-15-02-2018 `
  --output data/datasets/cicids2018/Thursday-15-02-2018.archive.json

.\.venv\Scripts\python.exe -m tools.cicids_archives fetch `
  data/datasets/cicids2018/Thursday-15-02-2018.archive.json `
  --member pcap/UCAP172.31.69.25 `
  --output data/datasets/cicids2018/Thursday-15-02-2018.victim-172.31.69.25.pcap
```

Supported starter catalogs cover February 14 (SSH/FTP brute force), February 15
(DoS), February 21 (DDoS), and March 2 (botnet). Defaults cap a selected member at
256 MiB compressed and 1 GiB extracted; larger members require explicit budget
arguments. Repeat operations with fresh output paths; existing files and failed
partial files are preserved for inspection.

The private starter manifest at
`data/datasets/cicids2018/starter-capture-manifest.json` records three downloaded
victim captures, totaling about 1.09 GB: February 14, February 15, and March 2.
The acquisition manifest records the initial unreviewed captures. Per-flow
curation and extraction evidence live under `data/datasets/public-import`.
Checks detected incomplete final packet
records in the two Ubuntu source captures, despite valid archive CRCs. Preserve
the originals and record any subsequent trimming or exclusions explicitly.
The February 21 DDoS capture was cataloged but not downloaded because its members
expand to approximately 18.3 GB and 2.1 GB.

Run the pinned production Zeek version offline before converting public captures.
Record the image, checksum handling, command, input hashes, and capture quality.
Verify published attack identities, timezones, and actual timing against packet
or system-log evidence before assigning labels. A scenario name or an entire
attack-day capture is not a per-flow truth label. Leave ambiguous traffic
unlabeled; retain conversion rejections for review. Dataset/source citations
must accompany redistributed public data.

### Import CICIDS2017 and IoT-23

Keep original PCAPs, `GeneratedLabelledFlows.zip`, IoT scenario READMEs, and
`conn.log.labeled` files intact. File extensions are not a format guarantee:
the supplied CICIDS2017 `.pcap` files contain PCAPNG blocks, while IoT label files
can mix tabs and multi-space separators. The importer handles both label layouts
and excludes explicitly empty CIC CSV rows without assigning them a benign label.

For a bounded development corpus, sample original source labels reproducibly and
retain every packet of the selected bidirectional TCP/UDP tuples across the whole
capture. This preserves original packet bytes, timestamps, lengths, handshakes,
and repeated connections using those tuples. Fragments/non-TCP/UDP packets remain
as context. Sampling occurs within fixed capture groups and does not create a
deployment-prevalence evaluation set.

```powershell
.\.venv\Scripts\python.exe -m tools.subset_public_capture `
  data/datasets/cicids2017/Tuesday-WorkingHours.pcap `
  --labels-zip data/datasets/cicids2017/GeneratedLabelledFlows.zip `
  --member 'TrafficLabelling /Tuesday-WorkingHours.pcap_ISCX.csv' `
  --output data/datasets/public-import/tuesday-new-version --per-label 2000
```

On a Linux Docker host with the pinned image already cached, run:

```bash
bash training/run-zeek-offline.sh INPUT_CAPTURE NEW_OUTPUT_DIRECTORY
```

The helper uses the production image digest, checksum ignoring, JSON output,
network isolation, a read-only root filesystem, one CPU, and a 1 GiB memory limit.
It loads `training/zeek-tunnel-policy.zeek`, the sensor's VXLAN UDP 8472 decoding,
so inner pod connections are logged; the policy's hash is recorded with the run.
It records input/image/log hashes and command metadata; existing outputs are not
overwritten. It processes files offline and never replays packets onto the LAN.

Join the resulting JSON connection log to the original labels:

```powershell
.\.venv\Scripts\python.exe -m tools.public_labels `
  --conn data/datasets/public-import/tuesday-new-version/zeek/conn.log `
  --cic-labels data/datasets/public-import/tuesday-new-version/source-labels.jsonl `
  --source cicids2017-tuesday --output data/datasets/public-import/tuesday-new-version/labels
```

For IoT-23, replace `--cic-labels` with `--iot-labels PATH_TO_CONN_LOG_LABELED`.
`tools.public_labels` maps documented C&C to `BOTNET`, DDoS to `DOS_DDOS`, and
scanning to `OTHER_ATTACK`; infection or a malware-family name alone never labels
every connection botnet. Credential guessing maps to `BRUTE_FORCE`; XSS/SQL
injection remain `OTHER_ATTACK`.

UIDs differ across Zeek runs. IoT joins require bidirectional endpoint/protocol
tuples and start timestamps within 1 ms, with agreeing overlapping source labels.
CICIDS2017 joins infer the source clock from unique tuples, requiring at least
20 anchors and 95% agreement, then account for minute precision and 12-hour CSV
ambiguity. Conflicting, unmapped, or unmatched connections stay unreviewed.
The supplied captures establish a three-hour clock offset; the CICIDS2018 sources
establish four hours. These offsets are evidence-derived, not blanket UTC assumptions.

Some CICIDS2018 CSVs omit endpoint identifiers. `--cse-csv` permits only signatures
unique in both inputs using protocol, destination port, directional packet counts,
exact microsecond duration, and aligned seconds; at least 20 anchors and 99%
clock agreement are required. No original CSV feature vector becomes model input.

Where row matches are insufficient for known campaigns, `tools.label_scenarios`
uses separately reviewed publisher endpoint/service/time specifications. The
brute-force rules in `training/cicids2018-bruteforce-scenarios.json` require clock
verification, exact actor/victim/service matches, and full connection containment
inside the published window. They also require failed-authentication evidence
from `ssh.log` or `ftp.log`; refused TCP handshakes alone are insufficient.
Conflicting row labels are excluded. SSH outcomes are Zeek's network inference,
not host authentication audit logs. Their provenance is distinct from direct row
matches, and label reports hash the protocol evidence used.

```powershell
.\.venv\Scripts\python.exe -m tools.label_scenarios `
  --conn data/datasets/public-import/cicids2018-bruteforce/zeek/conn.log `
  --reference-csv data/evaluation/cic.csv `
  --scenarios training/cicids2018-bruteforce-scenarios.json `
  --source cicids2018-bruteforce-20180214 `
  --output data/datasets/public-import/cicids2018-bruteforce/labels-auth-new-version
```

Every import writes labeled records, per-flow evidence, separate unmatched and
rejection files, and a reconciled report with hashes. Original source captures
remain unchanged. The two truncated CICIDS2018 files were handled with explicit
derivatives excluding only incomplete final records (65 and 307 bytes); derivation
manifests retain original/derivative hashes and exact discarded lengths.

### Train a separate candidate

Once reviewed data covers every class in both training and validation:

```powershell
.\.venv\Scripts\python.exe -m tools.train_model `
  data/datasets/nids-v1-prepared --output data/models/candidate-001 `
  --epochs 50 --batch-size 256 --patience 5 --seed 20261029
```

Training refuses incomplete class coverage before loading TensorFlow or creating
candidate output. It fits a fresh scaler and class weights on training data only,
uses validation loss for early stopping, and trains an `80 -> 128 -> 64 -> C`
dense baseline with dropout. The initial implementation loads reviewed records
into memory; use an explicitly documented, reproducible subset for large corpora.

The separate bundle contains the model, scaler, label encoder, feature order,
label map, and a report with dataset/code/artifact hashes, package versions,
configuration, and validation/regression metrics. It is reloaded and scored
through the actual production classifier to check compatibility. Test records
do not influence scaling, class weights, optimization, or early stopping, and
are not automatically scored. Deterministic settings and seeds are recorded;
cross-platform bit-for-bit reproducibility is not guaranteed.

The tools do not replace the root model files or deploy a candidate. Compare
against the existing model on whole held-out sessions before promotion. ICMPv6
continues to use the existing operational unvalidated policy.
`C` comes from the candidate class map. Before deploying a five-class candidate,
the dashboard's class list/cards must also be updated to display `BRUTE_FORCE`.
Training does not perform that production change automatically.

The current local development corpus is `data/datasets/nids-v4`, with its recipe
alongside it and a dataset card inside it. It has 49,761 training, 13,514 validation,
and 38 regression records; no final-test capture is assigned. Its independent
brute-force validation covers SSH only. The current candidate fails the benign
homelab regression and is unsuitable for deployment. Sanitized counts, results,
and the next collection priorities are recorded in `training/BASELINE_RESULTS.md`.

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
