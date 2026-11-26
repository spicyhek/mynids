# Changelog

The app follows [Semantic Versioning](https://semver.org/); README.md (Versioning) says when to bump which part.
1.9.0 is the first version the app reports. The versions before it were assigned afterwards, by applying the same
rules to the merged pull requests in order, and are not tagged. Pull requests that changed only CI, docs or
training tools (#1, #2, #11, #13, #16) are not listed.

## 1.10.0 (unreleased)

- New alert rule: a v2 attack label on a lone refused or aborted TCP attempt (no payload, at most 3 packets,
  `REJ` or an originator reset right after the handshake, from a source that is not scanning or flooding) is
  stored as BENIGN with `model_id` `<v2 id>+refused-attempt-rule`. It clears the false alerts on DNS retries over
  TCP that the router refuses and on Tailscale DERP probes cut short. `NIDS_SUPPRESS_REFUSED_ATTEMPTS=false`
  turns it off.
- Successful SSH logins are not alerts: with `NIDS_SSH_LOG_PATH` set, the converter marks flows whose login Zeek's
  `ssh.log` saw succeed (`ssh_auth_success`, a new optional flow field), and the app stores attack labels on them
  as BENIGN with `model_id` `<v2 id>+ssh-auth-rule`. This clears the BRUTE_FORCE and DOS_DDOS alerts on bursts of
  the operator's own logins. `NIDS_SUPPRESS_AUTHENTICATED_SSH=false` turns it off; a server without the field
  gets the flows resent without it.

## 1.9.0 (2026-11-22)

- Web scans: the sensor also exports every 4xx answer, the probe-path rule (`probe-path-v2`) covers any dotfile
  and more secret-file names, and the app groups one client's burst into a scan. New `GET /api/internal/web-scans`,
  scan counts in the public summary and a Web scans table on the dashboard.
  ([#21](https://github.com/spicyhek/mynids/pull/21))
- The app reports its version on `/healthz`, `/readyz`, the public summary and the dashboard header.

## 1.8.0 (2026-11-20)

- Dashboard overhaul, with ranges up to the last 7 days. ([#20](https://github.com/spicyhek/mynids/pull/20))

## 1.7.0 (2026-11-19)

- Routine ICMPv6 is recorded as benign by a rule, and the summary breaks unvalidated flows down by reason.
  ([#19](https://github.com/spicyhek/mynids/pull/19))

## 1.6.0 (2026-11-19)

- `/healthz` returns the deployed release in `X-Release-ID` for mybuilds.
  ([#18](https://github.com/spicyhek/mynids/pull/18))

## 1.5.0 (2026-11-10)

- The Keras model stops running in shadow, and by default BOTNET predictions and flows v2 cannot judge are stored as
  unvalidated (`NIDS_BOTNET_ALERTS`, `NIDS_V2_UNDECIDED` restore the earlier behavior). A changed default that
  keeps callers working, so minor. ([#17](https://github.com/spicyhek/mynids/pull/17))

## 1.4.0 (2026-11-10)

- Web-probe detection in the sensor's converter, with `POST` and `GET /api/internal/web-probes`.
  ([#15](https://github.com/spicyhek/mynids/pull/15))

## 1.3.1 (2026-11-10)

- An allow rule stops repeated benign BOTNET alerts for lone SYNs. ([#14](https://github.com/spicyhek/mynids/pull/14))

## 1.3.0 (2026-11-07)

- The baseline-v2 tree model can be made operational, with the Keras model in shadow (Keras stays the default).
  ([#12](https://github.com/spicyhek/mynids/pull/12))

## 1.2.1 (2026-10-30)

- The converter skips decoded VXLAN tunnel carriers, which counted each packet twice.
  ([#10](https://github.com/spicyhek/mynids/pull/10))

## 1.2.0 (2026-10-29)

- Shadow model and `GET /api/internal/shadow/summary`. ([#9](https://github.com/spicyhek/mynids/pull/9))

## 1.1.1 (2026-10-27)

- Fix an intermittent 502 from the summary endpoint. ([#8](https://github.com/spicyhek/mynids/pull/8))

## 1.1.0 (2026-10-27)

- ICMPv6 flows are recorded as unvalidated, and `GET /api/internal/events` lists stored events.
  ([#7](https://github.com/spicyhek/mynids/pull/7))

## 1.0.2 (2026-10-27)

- Correct the Zeek ICMPv6 protocol mapping. ([#6](https://github.com/spicyhek/mynids/pull/6))

## 1.0.1 (2026-10-26)

- Zero the timestamp feature before inference, as the model was trained, and add a model verification tool.
  ([#5](https://github.com/spicyhek/mynids/pull/5))

## 1.0.0 (2026-10-23)

- The first stable contract: ingestion requires `flow_id`, `event_time` and `source` and rejects unknown fields, so
  older sensors are refused. Also new storage, exporter recovery, `/readyz` and dashboard changes.
  ([#4](https://github.com/spicyhek/mynids/pull/4))

## 0.x (2026-03-11 to 2026-10-05)

- Initial development: the Keras model, the dashboard, CI/CD and the flow activity section
  ([#3](https://github.com/spicyhek/mynids/pull/3)).
