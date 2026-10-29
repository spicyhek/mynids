# Five-class development baseline

Recorded October 29, 2026. This experiment keeps the production converter's
80 ordered inputs and trains five outputs: `BENIGN`, `BOTNET`, `BRUTE_FORCE`,
`DOS_DDOS`, and `OTHER_ATTACK`. The production four-class artifacts are unchanged.

## Data

The private prepared version is `data/datasets/nids-v4`. All model features come
from fresh Zeek extraction of raw public captures, using the production image
digest and converter. Original publisher labels provide evidence; source CSV
feature vectors and model predictions are never used as training inputs or labels.

| Class | Train | Validation | Regression |
| --- | ---: | ---: | ---: |
| BENIGN | 23,214 | 2,451 | 38 |
| BOTNET | 8,222 | 6,706 | 0 |
| BRUTE_FORCE | 2,880 | 4,000 | 0 |
| DOS_DDOS | 15,393 | 235 | 0 |
| OTHER_ATTACK | 52 | 122 | 0 |
| Total | 49,761 | 13,514 | 38 |

Capture groups remain separate: CICIDS2017 Tuesday/Thursday, IoT-23 Hakai 8-1,
and CSE-CIC-IDS2018 February 15 are training; IoT-23 Mirai 34-1 and CSE February 14
are validation. Previously inspected homelab records are regression only.
There is no untouched final-test set. Label-stratified sampling makes these
class proportions unsuitable for estimating deployment alert volume.

CICIDS2017 labels use endpoint tuples and independently aligned minute times.
IoT-23 labels use tuples and subsecond times with consistent overlapping labels.
CSE2018 row joins require packet/duration metadata unique in both sources and
verified clock alignment because these CSVs omit endpoint identifiers.
Ambiguous or unmatched observations remain separate and unreviewed.

CSE2018 brute-force positives additionally require published actor/victim/service
windows and observed failed-authentication evidence. Refused FTP handshakes were
excluded from that credential-attempt corpus. SSH evidence is Zeek's inference
from network traffic, not host audit logs. Earlier campaign-only labeling and its
failed candidate are preserved as historical versions. The revised training and
homelab regression files are byte-identical to the earlier dataset; only the
validation curation changed, based on protocol evidence.

Training brute-force records include FTP, SSH and HTTP. Validation brute-force
records cover SSH only. OTHER_ATTACK training has just 52 records and different
behaviors from validation. Dataset readiness checks establish class coverage,
not adequate representation or reliable generalization.

## Candidate result

The separate bundle is `data/models/five-class-baseline-v2`. A dense
`80 -> 128 -> 64 -> 5` baseline used a training-only scaler and balanced class
weights, batch size 256, seed 20261029, and validation-loss early stopping with
patience 5. Training ran six epochs and restored the first epoch. Validation
therefore influences the model and is not an independent final test.

| Check | Result |
| --- | ---: |
| Five-class validation accuracy | 80.75% |
| Validation macro F1 | 0.562 |
| Validation benign false positives | 663 / 2,451 (27.05%) |
| Homelab benign false positives, candidate | 31 / 38 |
| Homelab benign false positives, existing model | 3 / 38 |

The candidate's homelab false positives are all OTHER_ATTACK. The sparse class
has a large balanced training weight; that is a possible contributor, not an
established cause. Raw accuracy cannot be compared directly with the four-class
model, which has no separate BRUTE_FORCE output. Nor can the revised validation
accuracy establish improvement over the earlier campaign-only validation: its
label criteria and protocol coverage changed.

Do not deploy this candidate. It loads successfully through the production
classifier but fails the operational benign regression.

## Next collection priorities

1. Collect additional homelab benign sessions for training, covering uploads,
   downloads, browsing, administration, idle/control traffic and background jobs.
   Label them with an activity timeline and protocol evidence. Preserve the
   existing 38 cases as regression.
2. Add independently labeled OTHER_ATTACK examples and enough benign examples
   from each source to assess whether the model is learning dataset identity.
3. Add separate FTP and web brute-force validation captures, plus independent
   DoS/DDoS scenarios. Keep related campaigns together by capture group.
4. Reserve fresh complete sessions as a final test before any further model
   selection. Report per-class precision/recall, benign false-positive rate,
   and per-session alert volume rather than overall accuracy alone.

Captures, endpoints, label evidence and model bundles stay in ignored `data/`.
The reusable tooling, configuration templates and this aggregate report may be
committed. A private backup is needed for artifacts that Git intentionally omits.

Sources: [CICIDS2017](https://www.unb.ca/cic/datasets/ids-2017.html),
[CSE-CIC-IDS2018](https://www.unb.ca/cic/datasets/ids-2018.html),
[IoT-23](https://www.stratosphereips.org/datasets-iot23).

## Tree candidate on nids-v5 (zeek-conn-window-v2)

Recorded October 29, 2026. `data/models/v2-tree-baseline-v1` is a separate
`HistGradientBoostingClassifier` (300 iterations, no early stopping, balanced
sample weights from training rows only) trained with `tools/train_tree_model.py`
on `nids-v5`: 64 inputs, five classes, plus 1,164 homelab `allowlist-benign` training
rows. Validation was not used for fitting or model choice. It is still not an
untouched final test. Serving cannot load this candidate.

| Check | Current production model (v1, 4 classes) | Tree candidate (v2) |
| --- | ---: | ---: |
| Validation attacks flagged as any attack | 36.4% | 67.5% |
| Validation benign false positives | 8 / 2,451 | 23 / 2,440 |
| Validation SSH brute force recall | 0 (all called DoS) | 100% (precision 99.9%) |
| Validation botnet (Mirai) recall | 0 | 0 |
| 38-case homelab regression false positives | 3 | 0 |
| Unlabeled homelab capture A (0.5 h), alerts/hour | 308 | 4 |
| Unlabeled homelab capture B (2 h), alerts/hour | 238 | 2 |

The alert-volume captures are homelab sessions that are not training sources.
Alerts are predictions, not confirmed attacks or confirmed false alarms. The
current model's alerts are mostly DoS on ports 80 and 443. The tree's few alerts are
mostly a smart-speaker service rejecting connections on TCP 1400.

Leave-one-source-out, any-attack recall on the held-out capture: CICIDS2017 Tuesday
0.99, CSE2018 SSH brute force 1.00 (typed as another attack), CSE2018 DoS 0.69,
IoT-23 Mirai 0.53, IoT-23 Hakai and CICIDS2017 Thursday about 0. Held-out benign
false positives were at most 2.7% (Mirai). The held-out homelab session's rate
was 0.26%.

Known gaps: botnet does not transfer between the two IoT-23 captures; OTHER_ATTACK
has 52 training rows and a class weight of about 196; benign SSH is nearly
absent; and there is no final test. Do not deploy. The next step is a
contract-aware shadow path, plus a reserved final-test session.
