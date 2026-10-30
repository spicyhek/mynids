# Capture packets and an activity journal

Use `tools/capture_session.py` on the Linux host running the sensor. It requires
Python 3.9+ and tcpdump; there are no Python packages to install. Only `capture`
needs sudo. The tool does not change network settings, run attacks, contact the
NIDS API, train a model, or assign ground-truth labels.

## 1. Copy the script and start capture

From PowerShell in the repository, replace the SSH destination with your sensor's
management address:

```powershell
scp .\tools\capture_session.py user@sensor-management-address:~/capture_session.py
ssh user@sensor-management-address
```

In that SSH terminal, run the following. The example captures for 30 minutes,
uses approximately 1 GiB of PCAP storage, and reserves 1 GiB of free disk space.
The output root's parent must already exist. An existing output root must belong
to your ordinary user; existing captures are never reused.

```bash
sudo python3 "$HOME/capture_session.py" capture \
  --interface eth0 \
  --output-root "$HOME/nids-captures" \
  --purpose train \
  --duration 1800 \
  --max-mib 1024 \
  --min-free-mib 1024
```

Wait for `READY`. Copy the exact `SESSION=...` path. Keep this terminal open; the
process runs in the foreground and must finish its packet audit before sealing.
Use a separate SSH terminal for activity commands. Use `validation` or `test` for
separate future sessions reserved for those purposes; keep related sessions in
one dataset split. A purpose is recorded intent, not a complete dataset split plan.

The capture uses `-s 0`, packet-buffered output, a 32 MiB capture buffer and no
traffic filter. It rotates into new numbered files at 100 decimal MB and never
wraps around to overwrite earlier files. Storage and free-space limits are
polled every 250 ms, so usage can exceed the requested budget. Capture ends at
the time/storage limit, a stop request, Ctrl+C, or a capture failure. Tcpdump
drops privileges to the invoking user after opening the capture device.
These options follow the [upstream tcpdump manual](https://github.com/the-tcpdump-group/tcpdump/blob/master/tcpdump.1.in).

Use the same interface as production. Host `eth0` capture does not establish
visibility of the whole LAN. For transfers to the sensor, target its **wired**
address. For requests originating on the sensor, bind the client to that address
when possible. Merely browsing on another device may produce no visible traffic.

## 2. Record activity in a second terminal

Set these values to the printed session path and your real device addresses.
The addresses below are documentation examples and must be replaced.

```bash
session="$HOME/nids-captures/PASTE-PRINTED-SESSION-ID"
sensor_ip='192.0.2.10'
laptop_ip='192.0.2.20'
```

For a command executed **on the sensor**, `run` records the command, UTC start/end,
origin/destination, exit code, timeout/failure and stdout/stderr. Run it as your
normal user. Arguments are executed directly, without an implicit shell.

This small HTTPS request is a visibility/connectivity check, not a bulk download:

```bash
python3 "$HOME/capture_session.py" run \
  --session "$session" --name https-check \
  --source "$sensor_ip" --destination example.com --protocol tcp --port 443 \
  --timeout 60 --note 'Known HTTPS request, bound to the wired source address' \
  -- curl --interface "$sensor_ip" --fail --location --silent --show-error \
     --output /dev/null \
     --write-out 'http=%{http_code} remote_ip=%{remote_ip} bytes=%{size_download} seconds=%{time_total}\n' \
     https://example.com/
```

For a bulk download, substitute a known file URL you control or are authorized
to download, increase the timeout, and record the file size in `--note`. For
an SSH command from this host, bind its source with `ssh -b "$sensor_ip" ...`.
Capture regular behavior at realistic rates; do not repeatedly fetch a tiny URL
and treat that as coverage of uploads, downloads or interactive administration.

For a task performed **on your laptop**, use manual markers on the sensor:

```bash
python3 "$HOME/capture_session.py" begin \
  --session "$session" --name scp-upload \
  --source "$laptop_ip" --destination "$sensor_ip" --protocol tcp --port 22 \
  --note 'Upload a known test file from the laptop; record its size and destination filename'
```

Copy the returned `activity_id`. Perform the upload from your laptop, targeting
the wired sensor address. Then close the activity in the sensor terminal:

```bash
python3 "$HOME/capture_session.py" end \
  --session "$session" --id PASTE-ACTIVITY-ID --outcome completed \
  --note 'Record actual file size, destination filename and observed result'
```

Use `failed`, `aborted`, or `unknown` when appropriate. A manual `completed`
entry is an operator report; it is not an automatically verified command result.
For downloads, record the actual originator and responder: an SCP client can be
the TCP originator while receiving file data. Note upload/download direction
explicitly instead of swapping endpoint roles based on byte direction.

Additional context and open-activity inspection:

```bash
python3 "$HOME/capture_session.py" note --session "$session" \
  --text 'Record device, background jobs, application, file sizes, unexpected failures or timing corrections'
python3 "$HOME/capture_session.py" status --session "$session"
```

All timestamps are recorded on the sensor in UTC, including markers sent from
another terminal. The bundle includes the clock synchronization status. For
separately collected client/server audit logs, record their clock offsets too.
Commands, notes and output are preserved: keep credentials out of arguments and
outputs, use SSH keys where practical, and keep the bundle private.

## 3. Suggested first training session

Treat this as a schedule to follow and document, not an automatic activity runner.
The journal must record what actually happened. Leave a few minutes at each edge
of the capture so known connections can finish before capture stops.

| Approximate minutes | Activity | Evidence to record |
| --- | --- | --- |
| 0–3 | Leave normal background services running | Device and known jobs; no blanket benign label |
| 3–7 | Ordinary SSH administration | Client/server addresses, commands or task, outcome |
| 7–12 | Known HTTPS requests or browsing visible to the sensor | Application, hostnames, resulting IPs where available |
| 12–18 | A few ordinary downloads of different sizes | Client/server, file sizes and completion status |
| 18–24 | A few uploads to the wired sensor address | Client/server, sizes, filenames and completion status |
| 24–28 | Representative normal work | Concurrent jobs and approximate timing |
| 28–30 | Finish activities and allow connections to close | Actual end markers; no new large transfers |

Repeat with different workloads/devices on later days. Keep the old 38 reviewed
homelab cases as regression. Reserve fresh complete sessions and independent
attack captures for validation/final test before model selection. This framework
does not generate or label attack traffic.

## 4. Finish, seal and copy the evidence

Close activities after their real completion. Capture stops automatically; to
stop early, use the second terminal:

```bash
python3 "$HOME/capture_session.py" stop --session "$session"
```

Wait for the capture terminal's final report. Packet audits/hash computation can
take time. Review `status` and `quality_flags`. They report missing/nonzero kernel
drops, packet-count discrepancies, snapshot truncation, incomplete packet records,
unconfirmed clock synchronization or unclean termination. A stop at the storage
limit may cut a workload short; preserve that fact instead of inventing a success.
If an activity ends after capture, sealing adds a capture-boundary warning.

Once all activities are closed and capture has finalized:

```bash
python3 "$HOME/capture_session.py" seal --session "$session"
python3 "$HOME/capture_session.py" verify --session "$session"
```

Sealing blocks further journal writes through this tool and records SHA-256 hashes.
It can preserve a session with quality warnings for review; it does not certify
it as usable training data. Do not edit sealed files or add Zeek output inside
the sealed directory. Derivatives belong in a separate working directory.

Copy the entire directory back from PowerShell. Replace the placeholders:

```powershell
scp -r user@sensor-management-address:/home/user/nids-captures/SESSION-ID .\data\evaluation\sessions\
.\.venv\Scripts\python.exe .\tools\capture_session.py verify `
  --session .\data\evaluation\sessions\SESSION-ID
```

| File | Purpose |
| --- | --- |
| `traffic.pcap`, `traffic.pcap1`, … | Original full-snapshot packet files |
| `activity.jsonl` | UTC activity markers, endpoints, commands, results and notes |
| `activity-*.stdout.log`, `activity-*.stderr.log` | Command output for evidence review |
| `capture.json` | Interface, clock, capture arguments, source version, packet audits and quality flags |
| `capture.log` | Original tcpdump diagnostics and drop statistics |
| `capture-framework.py` | Exact standalone script used for this session |
| `session-manifest.json` | Sealed file sizes and hashes for copy-integrity checks |

## 5. Process all rotations together through Zeek

Use one chronological input for all rotations so connections crossing file
boundaries are reconstructed together. On a host with Wireshark's `mergecap`,
create a new working directory outside the sealed bundle:

```bash
work="${session}-processing"
(
  set -euo pipefail
  mkdir -m 700 "$work"
  cp "$session/session-manifest.json" "$work/source-session-manifest.json"
  mergecap --version > "$work/mergecap-version.txt"
  mergecap -F pcap -w "$work/input.pcap" "$session"/traffic.pcap*
  sha256sum "$work/input.pcap" > "$work/input.sha256"
  bash training/run-zeek-offline.sh "$work/input.pcap" "$work/zeek"
)
```

`mergecap` merges by frame timestamps by default; no packet-length cap is applied
here. See its [official manual](https://www.wireshark.org/docs/man-pages/mergecap.html).
The Zeek helper requires the pinned image already cached on that Linux Docker
host. It uses checksum ignoring (`-C`) for the previously observed offload issue,
decodes K3s VXLAN on UDP 8472 with `training/zeek-tunnel-policy.zeek` (the same
decoding as the sensor), and records input/image/policy/log hashes. Preserve any merge error and do not process
a partial input. If only one PCAP exists, it can be passed directly to the helper.

Finally, match journal evidence to connection tuples and protocol logs. Retain
unmatched background traffic as unreviewed. A connection overlapping an activity
window is not automatically attributable to that activity, and a successful
normal command does not establish every connection in the window as benign.
Only reviewed rows should enter a new version of the training recipe.

The reusable script, tests and this guide can be committed. Captures, actual
endpoint details, journals and derived data remain under ignored `data/`; keep
a separate private backup.

## 6. Optional: allowlist benign labels for a whole session

Per-flow review is too slow to cover background traffic. A weaker tier,
`allowlist-benign`, labels a connection BENIGN only when a written rule explains
it: endpoints, ports and connection state, plus TLS server name, HTTP request or
DNS query evidence where the rule asks for it. Rules describe traffic that is
expected on this network; they do not claim that each connection was inspected.

1. Copy `training/homelab-benign-policy.example.json` to ignored `data/labeling/`.
   Pin the session ID and the `session-manifest.json` hash, and write the
   attestation yourself: confirm that no deliberate attack, scan or load test ran
   during the capture.
2. List journal activities that were attacks or drills under
   `exclusions.activities`, and any unexplained period under `exclusions.windows`.
   The fan-out guard leaves an originator unlabeled for the whole session if it
   reaches too many distinct ports or hosts within a minute.
3. Run the labeler against the sealed bundle and the session's Zeek logs:

   ```powershell
   .\.venv\Scripts\python.exe -m tools.label_homelab_benign `
     --session .\data\evaluation\sessions\<session> `
     --zeek <zeek log directory> --policy .\data\labeling\<policy>.json `
     --output .\data\labeling\<session>\allowlist-v1 --source session-<session>
   ```

4. Read `report.json`. `unmatched_groups` lists unexplained traffic. Add a rule
   only when you can state why that traffic is expected, then label into a new
   version directory. Never add a rule just to raise coverage.
5. In the dataset recipe, set `"label_tier": "allowlist-benign"` on the source.
   Preparation refuses tiered rows from a source that does not declare the tier.
   Keep each session's whole capture group in one split, and keep the 38-case
   regression session out of training.

Outer VXLAN carriers are counted and skipped, as in the v2 feature contract.
