# mynids

This is a Network Intrusion Detection System made for my homelab cluster. It's trained on the CICIDS2018 dataset using a multi-layer perceptron across 9 million rows and 4 classes, getting a validation accuracy of 97% and an averaged f1-score of 0.98.

The service has two surfaces:

- Public:
  - `GET /`
  - `GET /api/public/summary`
  - `GET /healthz`
- Private:
  - `POST /api/internal/flows`

The site intentionally exposes only aggregate statistics.

## Runtime Layout

- `app/`: FastAPI service, SQLite stats storage, webpage, and model loading
- `sensor/`: private flow helper for posting batches to the ingestion endpoint
- root artifacts:
  - `cicids2018_dense_model.keras`
  - `scaler.joblib`
  - `feature_order.json`
  - `label_map.json`
  - `label_encoder.joblib`

All 80 features in `feature_order.json` are required for each flow. Since all 80 features are not possible to see directly with Zeek, some calculations and approximations are made:

- `direct`: copied directly from Zeek with light normalization
- `derived`: computed from one or more Zeek fields
- `approx`: filled using a documented approximation because Zeek `conn.log` does not expose the exact CICIDS source signal
- `zero`: unavailable from Zeek `conn.log`, `0.0` for now

| CICIDS feature      | Zeek source                   | strategy | notes                                           |
| ------------------- | ----------------------------- | -------- | ----------------------------------------------- |
| `dst_port`          | `id.resp_p`                   | direct   | responder port                                  |
| `protocol`          | `proto`                       | derived  | mapped to IP protocol number                    |
| `timestamp`         | `ts`                          | derived  | epoch timestamp converted to microseconds       |
| `flow_duration`     | `duration`                    | derived  | seconds converted to microseconds               |
| `tot_fwd_pkts`      | `orig_pkts`                   | direct   | originator packet count                         |
| `tot_bwd_pkts`      | `resp_pkts`                   | direct   | responder packet count                          |
| `totlen_fwd_pkts`   | `orig_ip_bytes`               | direct   | falls back to `orig_bytes`                      |
| `totlen_bwd_pkts`   | `resp_ip_bytes`               | direct   | falls back to `resp_bytes`                      |
| `fwd_pkt_len_max`   | `orig_ip_bytes`, `orig_pkts`  | approx   | uses forward mean packet length                 |
| `fwd_pkt_len_min`   | `orig_ip_bytes`, `orig_pkts`  | approx   | uses forward mean packet length                 |
| `fwd_pkt_len_mean`  | `orig_ip_bytes`, `orig_pkts`  | derived  | bytes per packet                                |
| `fwd_pkt_len_std`   | unavailable                   | zero     | Zeek `conn.log` lacks packet-level variance     |
| `bwd_pkt_len_max`   | `resp_ip_bytes`, `resp_pkts`  | approx   | uses backward mean packet length                |
| `bwd_pkt_len_min`   | `resp_ip_bytes`, `resp_pkts`  | approx   | uses backward mean packet length                |
| `bwd_pkt_len_mean`  | `resp_ip_bytes`, `resp_pkts`  | derived  | bytes per packet                                |
| `bwd_pkt_len_std`   | unavailable                   | zero     | Zeek `conn.log` lacks packet-level variance     |
| `flow_byts_s`       | totals, `duration`            | derived  | total IP bytes divided by duration              |
| `flow_pkts_s`       | totals, `duration`            | derived  | total packets divided by duration               |
| `flow_iat_mean`     | `duration`, total packets     | approx   | average total flow inter-arrival time           |
| `flow_iat_std`      | unavailable                   | zero     | no packet timeline in `conn.log`                |
| `flow_iat_max`      | `duration`, total packets     | approx   | set to average IAT                              |
| `flow_iat_min`      | `duration`, total packets     | approx   | set to average IAT                              |
| `fwd_iat_tot`       | `duration`, `orig_pkts`       | approx   | total forward IAT span                          |
| `fwd_iat_mean`      | `duration`, `orig_pkts`       | approx   | average forward IAT                             |
| `fwd_iat_std`       | unavailable                   | zero     | no packet timeline in `conn.log`                |
| `fwd_iat_max`       | `duration`, `orig_pkts`       | approx   | set to average forward IAT                      |
| `fwd_iat_min`       | `duration`, `orig_pkts`       | approx   | set to average forward IAT                      |
| `bwd_iat_tot`       | `duration`, `resp_pkts`       | approx   | total backward IAT span                         |
| `bwd_iat_mean`      | `duration`, `resp_pkts`       | approx   | average backward IAT                            |
| `bwd_iat_std`       | unavailable                   | zero     | no packet timeline in `conn.log`                |
| `bwd_iat_max`       | `duration`, `resp_pkts`       | approx   | set to average backward IAT                     |
| `bwd_iat_min`       | `duration`, `resp_pkts`       | approx   | set to average backward IAT                     |
| `fwd_psh_flags`     | `history`                     | derived  | count of `P` in Zeek history                    |
| `bwd_psh_flags`     | `history`                     | derived  | count of `p` in Zeek history                    |
| `fwd_urg_flags`     | `history`                     | derived  | count of `U` in Zeek history                    |
| `bwd_urg_flags`     | `history`                     | derived  | count of `u` in Zeek history                    |
| `fwd_header_len`    | `orig_ip_bytes`, `orig_bytes` | derived  | IP bytes minus payload bytes                    |
| `bwd_header_len`    | `resp_ip_bytes`, `resp_bytes` | derived  | IP bytes minus payload bytes                    |
| `fwd_pkts_s`        | `orig_pkts`, `duration`       | derived  | forward packets per second                      |
| `bwd_pkts_s`        | `resp_pkts`, `duration`       | derived  | backward packets per second                     |
| `pkt_len_min`       | directional packet means      | approx   | minimum of available directional means          |
| `pkt_len_max`       | directional packet means      | approx   | maximum of available directional means          |
| `pkt_len_mean`      | total bytes, total packets    | derived  | aggregate mean packet length                    |
| `pkt_len_std`       | unavailable                   | zero     | no packet-level variance in `conn.log`          |
| `pkt_len_var`       | unavailable                   | zero     | no packet-level variance in `conn.log`          |
| `fin_flag_cnt`      | `history`                     | derived  | count of `F` and `f`                            |
| `syn_flag_cnt`      | `history`                     | approx   | counts `S`, `s`, `H`, `h`                       |
| `rst_flag_cnt`      | `history`                     | derived  | count of `R` and `r`                            |
| `psh_flag_cnt`      | `history`                     | derived  | count of `P` and `p`                            |
| `ack_flag_cnt`      | `history`                     | derived  | count of `A` and `a`                            |
| `urg_flag_cnt`      | `history`                     | derived  | count of `U` and `u`                            |
| `cwe_flag_count`    | unavailable                   | zero     | not exposed by `conn.log`                       |
| `ece_flag_cnt`      | unavailable                   | zero     | not exposed by `conn.log`                       |
| `down_up_ratio`     | `resp_pkts`, `orig_pkts`      | derived  | backward packets divided by forward packets     |
| `pkt_size_avg`      | total bytes, total packets    | derived  | same value as `pkt_len_mean`                    |
| `fwd_seg_size_avg`  | forward bytes, `orig_pkts`    | derived  | same value as `fwd_pkt_len_mean`                |
| `bwd_seg_size_avg`  | backward bytes, `resp_pkts`   | derived  | same value as `bwd_pkt_len_mean`                |
| `fwd_byts_b_avg`    | unavailable                   | zero     | Zeek `conn.log` has no bulk-window metric       |
| `fwd_pkts_b_avg`    | unavailable                   | zero     | Zeek `conn.log` has no bulk-window metric       |
| `fwd_blk_rate_avg`  | unavailable                   | zero     | Zeek `conn.log` has no bulk-window metric       |
| `bwd_byts_b_avg`    | unavailable                   | zero     | Zeek `conn.log` has no bulk-window metric       |
| `bwd_pkts_b_avg`    | unavailable                   | zero     | Zeek `conn.log` has no bulk-window metric       |
| `bwd_blk_rate_avg`  | unavailable                   | zero     | Zeek `conn.log` has no bulk-window metric       |
| `subflow_fwd_pkts`  | `orig_pkts`                   | approx   | single Zeek record treated as one subflow       |
| `subflow_fwd_byts`  | `orig_ip_bytes`               | approx   | single Zeek record treated as one subflow       |
| `subflow_bwd_pkts`  | `resp_pkts`                   | approx   | single Zeek record treated as one subflow       |
| `subflow_bwd_byts`  | `resp_ip_bytes`               | approx   | single Zeek record treated as one subflow       |
| `init_fwd_win_byts` | unavailable                   | zero     | TCP window size not exposed in `conn.log`       |
| `init_bwd_win_byts` | unavailable                   | zero     | TCP window size not exposed in `conn.log`       |
| `fwd_act_data_pkts` | `orig_pkts`                   | approx   | uses forward packet count                       |
| `fwd_seg_size_min`  | forward bytes, `orig_pkts`    | approx   | uses forward mean packet length                 |
| `active_mean`       | `duration`                    | approx   | single active period treated as entire duration |
| `active_std`        | unavailable                   | zero     | no multi-burst timeline in `conn.log`           |
| `active_max`        | `duration`                    | approx   | same as active mean                             |
| `active_min`        | `duration`                    | approx   | same as active mean                             |
| `idle_mean`         | unavailable                   | zero     | no idle burst segmentation in `conn.log`        |
| `idle_std`          | unavailable                   | zero     | no idle burst segmentation in `conn.log`        |
| `idle_max`          | unavailable                   | zero     | no idle burst segmentation in `conn.log`        |
| `idle_min`          | unavailable                   | zero     | no idle burst segmentation in `conn.log`        |
| `src_port`          | `id.orig_p`                   | direct   | originator port                                 |
