# Live-host verification — container run (worker 4)

- **Branch:** `fix/live-host-container`
- **Base:** `884f590` (`test: kill 180 calibration remainder mutants, baseline 3, counts 487 -> 490`)
- **Date:** 2026-11-08, times UTC (local CET = UTC+1)
- **Scope:** container re-check of the bare-server API surface verified by
  workers 2 (`docs/live-host-api-verification.md`, branch
  `fix/live-host-api`) and 3 (`docs/LIVE_HOST_UI_20261108.md`, branch
  `fix/live-host-ui`). Same endpoints, same request payloads, same
  failure modes — against `docker run --rm -p 127.0.0.1:8765:8765
  textforensics:local`.

## Verdict: BLOCKED — the container cannot start on this VM

**No container run happened.** Every `docker run` attempt fails at
container-create time, before any process starts, with exit 125 and
the OCI runtime error below. Steps 2–4 of the brief (health timing,
endpoint transcripts, logs, restart) could not execute at all, so
there is no container-vs-bare-server comparison table to report —
nothing was measured. This is a host-runtime defect, not a repo or
image defect: the image is verified present and intact (§1), the
documented command is correct, and the failure is identical for a
trivial entrypoint and for `--user root`, i.e. independent of the
image, its command, and its user (§3–§4).

**No files outside `docs/` were touched, and no host fix was applied.**
The proposed fix (§5) is a one-line host-side shim change that needs
the parent/coordinator's approval; it is outside this worker's
docs-only scope and touches a runtime shared with sibling workers.
After it is applied, steps 2–4 need a fresh worker run.

## 1. Image verification — PRESENT, intact, no restore needed

The image was present in the local daemon when work started; no
rebuild and no tarball restore was required.

```console
$ docker images textforensics:local
IMAGE                 ID             DISK USAGE   CONTENT SIZE   EXTRA
textforensics:local   1b846388bad8        146MB             0B

$ docker image inspect textforensics:local \
    --format '{{.Id}} {{.Size}} {{.Config.Entrypoint}} {{.Config.Cmd}} {{.Config.User}}'
sha256:1b846388bad89323227a60ed621fa2178b937135f7d612a2d0b7d849ca6c4c92 145892966 [textforensics] [serve] textforensics:textforensics

$ docker image inspect textforensics:local --format '{{json .Config.Healthcheck}}'
{"Test":["CMD-SHELL","python -c \"import os,urllib.request; urllib.request.urlopen('http://127.0.0.1:'+os.getenv('TEXTFORENSICS_PORT','8765')+'/healthz',timeout=2).read()\" || exit 1"],"Interval":30000000000,"Timeout":3000000000,"StartPeriod":5000000000,"Retries":3}
```

- ID `sha256:1b846388bad89323227a60ed621fa2178b937135f7d612a2d0b7d849ca6c4c92`
  (short `1b846388bad8`), size 145,892,966 bytes (146 MB) — matches the
  coordinator's record exactly.
- Entrypoint `[textforensics]`, Cmd `[serve]`, User
  `textforensics:textforensics`, HEALTHCHECK on `/healthz`
  (interval 30s, timeout 3s, start-period 5s, retries 3) — all as
  documented.
- Tarball restore path was checked but not needed:
  `~/workspace/lh-build-logs/textforensics-local.tar` still hashes to
  `b11c09217918cbf071b5e8157207e28f0ef0bcc828f18a32164a2a4e8903a4b0`
  (verified with `sha256sum` before the run attempts), matching the
  coordinator's record.

## 2. Host runtime — Docker 29.1.3, crun 1.14.1 via a runc→crun shim

```console
$ docker info
Server Version: 29.1.3
Storage Driver: vfs
Cgroup Driver: systemd / Cgroup Version: 2
Runtimes: io.containerd.runc.v2 runc
Default Runtime: runc
runc version: de537a7965bfbe9992e2cfae0baeb56a08128171

$ docker version --format '{{.Server.Version}}'
29.1.3

$ crun --version
crun version 1.14.1
commit: de537a7965bfbe9992e2cfae0baeb56a08128171

$ docker info --format 'Containers: {{.Containers}} Images: {{.Images}}'
Containers: 0 Images: 1
```

Note: `docker info` reports the shim's crun version/commit as the
"runc version" — the daemon's `runc` binary is not stock runc.

`/usr/bin/runc` (also `/usr/sbin/runc`, dated 2026-11-08 19:39) is a
bash shim that execs `/usr/bin/crun` after rewriting the OCI bundle
`config.json`. Its relevant behaviours, read from the script itself:

- `--no-new-keyring`, strips `--systemd-cgroup` and `--keep`.
- Rewrites `ociVersion` 1.2.x → 1.0.2 and deletes empty `blockIO`.
- **Removes the network namespace from the spec** — crun bringing up
  `lo` in a new net ns needs `CAP_NET_ADMIN`, absent from this cell's
  bounding set, so containers share the host network namespace.
- Intersects the spec's capability lists with the process bounding
  set (the cell lacks `CAP_NET_ADMIN`, `CAP_NET_RAW`,
  `CAP_SYS_PTRACE`, …).

This is a real OCI runtime running a real image — but it is **not**
stock Docker/runc networking: with the network namespace stripped,
`-p 127.0.0.1:8765:8765` performs no isolation (see §6).

`docker ps -a` is empty and `docker info` reports `Containers: 0`:
no container has ever run on this daemon. The build worker's evidence
is a build only — no `docker run` appears anywhere in
`~/workspace/lh-build-logs/`. The image has therefore **never been
executed** on this VM, in any form, before this worker's attempts.

## 3. Run attempts — all fail identically at create time

Attempt 1 — the documented command, detached:

```console
$ date -u '+START %Y-%m-%d %H:%M:%S UTC'
START 2026-11-08 19:48:52 UTC
$ docker run -d --rm -p 127.0.0.1:8765:8765 --name tf-lh-container textforensics:local
WARNING: IPv4 forwarding is disabled. Networking will not work.
b07232a11b0476bc54a4227c40507c6a61293d7a4e2f108f21e7d51149f52a68
docker: Error response from daemon: failed to create task for container: failed to create shim task: OCI runtime create failed: the sysctl `net.ipv4.ip_unprivileged_port_start` requires a new network namespace

Run 'docker run --help' for more information
exit=125
```

(The `b07232…` line is the container ID the daemon allocated before
the runtime create failed; `docker ps -a` afterwards is empty and
`docker inspect b07232…` returns "no such object" — nothing persisted.)

Attempt 2 — no `-p`, no `-d` (isolates the port mapping):

```console
$ docker run --rm textforensics:local
WARNING: IPv4 forwarding is disabled. Networking will not work.
docker: Error response from daemon: failed to create task for container: failed to create shim task: OCI runtime create failed: the sysctl `net.ipv4.ip_unprivileged_port_start` requires a new network namespace

Run 'docker run --help' for more information
exit=125
```

Attempt 3 — diagnostic, `--user root` (isolates the image user):

```console
$ date -u '+ROOT-DIAG-START %Y-%m-%d %H:%M:%S UTC'
ROOT-DIAG-START 2026-11-08 19:50:02 UTC
$ docker run -d --rm -p 127.0.0.1:8765:8765 --name tf-lh-rootdiag --user root textforensics:local
WARNING: IPv4 forwarding is disabled. Networking will not work.
662439274b0fc6481b56ef987ad0d28273728b929fa45ea9fb8775cb27768462
docker: Error response from daemon: failed to create task for container: failed to create shim task: OCI runtime create failed: the sysctl `net.ipv4.ip_unprivileged_port_start` requires a new network namespace

Run 'docker run --help' for more information
exit=125
```

Attempt 4 — diagnostic, trivial entrypoint (isolates the image entirely):

```console
$ docker run --rm --entrypoint /bin/true textforensics:local
WARNING: IPv4 forwarding is disabled. Networking will not work.
docker: Error response from daemon: failed to create task for container: failed to create shim task: OCI runtime create failed: the sysctl `net.ipv4.ip_unprivileged_port_start` requires a new network namespace

Run 'docker run --help' for more information
exit=125
```

Final re-attempt — the documented command verbatim, for a clean timestamped record:

```console
$ date -u '+FINAL-ATTEMPT %Y-%m-%d %H:%M:%S UTC'
FINAL-ATTEMPT 2026-11-08 19:51:03 UTC
$ docker run --rm -p 127.0.0.1:8765:8765 textforensics:local
WARNING: IPv4 forwarding is disabled. Networking will not work.
docker: Error response from daemon: failed to create task for container: failed to create shim task: OCI runtime create failed: the sysctl `net.ipv4.ip_unprivileged_port_start` requires a new network namespace

Run 'docker run --help' for more information
exit=125
$ date -u '+END %Y-%m-%d %H:%M:%S UTC'
END 2026-11-08 19:51:09 UTC
$ docker ps -a
CONTAINER ID   IMAGE     COMMAND   CREATED   STATUS    PORTS     NAMES
$ curl -s -m 2 http://127.0.0.1:8765/healthz; echo "curl-exit=$?"
curl-exit=7 (nothing listening, as expected)
```

| Attempt | Command variation | Result |
|---|---|---|
| 1, 19:48:52 UTC | Documented: `docker run -d --rm -p 127.0.0.1:8765:8765 textforensics:local` | exit 125, sysctl error |
| 2, ~19:49 UTC | `docker run --rm textforensics:local` (no `-p`) | exit 125, identical error |
| 3, 19:50:02 UTC | `--user root` | exit 125, identical error |
| 4, ~19:51 UTC | `--entrypoint /bin/true` | exit 125, identical error |
| 5, 19:51:03 UTC | Documented command verbatim | exit 125, identical error |

## 4. Diagnosis — why it fails

Causal chain, each link evidenced above:

1. **Docker/containerd puts `net.ipv4.ip_unprivileged_port_start=0`
   in the OCI spec's `linux.sysctl` for every created container by
   default** (Docker sets it to 0 for created containers so
   non-root users inside a container can bind low ports; it is a
   daemon default, not a user setting — `docker create` +
   `docker inspect` shows `HostConfig.Sysctls: null`, so it does not
   come from the command line).
2. **`net.ipv4.ip_unprivileged_port_start` is a per-network-namespace
   sysctl.** crun refuses to apply a namespaced sysctl unless the
   container has its own network namespace, and errors with exactly
   the message observed: "the sysctl
   `net.ipv4.ip_unprivileged_port_start` requires a new network
   namespace".
3. **The runc→crun shim deletes the network namespace from every
   spec** (see §2: crun cannot bring up `lo` without `CAP_NET_ADMIN`
   in this cell). The two behaviours are individually reasonable and
   jointly fatal: the spec always carries the sysctl, the spec never
   carries a network namespace, so **every `docker run` on this
   daemon fails at create time** — not just this image.
4. **The image is exonerated by the diagnostics:** attempt 4
   (`--entrypoint /bin/true`) fails identically, and attempt 3
   (`--user root`) fails identically, so the failure depends on
   neither the image's command nor its `textforensics` user.
5. **Why the build succeeded anyway:** BuildKit generates its own OCI
   spec for `RUN` steps (and the build used `--opt network=host`);
   its specs do not carry the daemon's default sysctl, so build
   steps never hit this path. Build success therefore says nothing
   about `docker run` on this VM.

No `docker run` invocation can succeed while both (1) and (3) hold:
the sysctl cannot be removed from the CLI (`--sysctl` only
adds/overrides; overriding to the same value does not help, since
crun refuses *any* namespaced sysctl without a new net namespace),
and `--network none` would not help either (the shim strips the
network namespace unconditionally, and a netns-less container would
have no network to probe anyway).

## 5. Proposed fix — host-side, needs approval, NOT applied

In `/usr/bin/runc` (and `/usr/sbin/runc`), in the same Python block
that already deletes empty `blockIO` from the bundle `config.json`,
also delete the default sysctl:

```python
sysctls = c.get("linux", {}).get("sysctl", {})
sysctls.pop("net.ipv4.ip_unprivileged_port_start", None)
```

Why this is safe for this image and this VM:

- The sysctl only lowers the first unprivileged port (default 1024)
  to 0, i.e. it only matters for binding ports **below 1024**.
  The server binds **8765**, so dropping the sysctl changes nothing
  for `textforensics:local`; it restores the kernel default (1024)
  inside the container's (shared) network namespace.
- It is the same class of edit the shim already makes (drop a
  spec entry that this cell cannot honour, where the entry is a
  no-op for the workload) — not a weakening of a security boundary
  the image relies on.
- It unblocks `docker run` in general on this daemon, not just this
  image, which is what the live-host verification needs.

Caveats for whoever applies it:

- The VM has rebooted twice today, wiping the root filesystem each
  time (Docker and `/usr/bin/runc` included) — the shim was
  re-installed after the last reboot. **Any fix to the shim must be
  re-applied after a reboot**, or it silently vanishes and the next
  container run fails the same way.
- The fix should be verified by re-running the exact documented
  command from §3 and then re-running this worker's steps 2–4 in
  full (health timing, endpoint transcripts, logs, restart).

Alternatives considered and rejected: running the container as root
(fails identically — the sysctl is a daemon default, not user-gated);
`--network none` (shim strips the namespace anyway; no network to
probe); running via `ctr`/BuildKit with a hand-built spec (would not
verify the documented `docker run` path, so it would not be the
verification this worker owes).

## 6. Caveats for the eventual re-run (when the fix lands)

- **Network isolation will still not be Docker's.** With the shim
  stripping the network namespace, the container shares the host net
  ns, so `-p 127.0.0.1:8765:8765` performs no mapping or isolation;
  the "loopback-only" property then rests on the application binding
  `127.0.0.1` (its documented default), not on the publish flag.
  The re-run should confirm the listening socket is `127.0.0.1:8765`
  (e.g. `ss -tlnp`) rather than assuming `-p` did it, and should
  record this honestly.
- **`WARNING: IPv4 forwarding is disabled. Networking will not work.`
  appears on every invocation.** With a shared host net ns it is
  likely cosmetic for loopback traffic, but the re-run should confirm
  `curl` to `127.0.0.1:8765` actually works rather than assuming the
  warning is benign.
- **The HEALTHCHECK start-period question is still open.** Worker 2
  measured ~15 s bare-server startup against a 5 s start-period
  (retries=3). Whether the container reaches `healthy`, and in how
  many seconds, is still unverified — it is the first thing the
  re-run must measure. No docs correction is proposed for the
  start-period until that measurement exists.
- **No docs correction is made by this worker.** `docs/INSTALLATION.md`
  (and `compose.yaml`'s loopback publish) describe the container
  command correctly; the failure is in the host runtime, not the
  docs. Worker 3 already corrected `INSTALLATION.md` on the UI side
  (image serves the API only, `GET /` → 404); nothing in this run
  contradicts or adds to that.

## 7. Still unverified — everything in steps 2–4

Because no container ever started, **all** of the following remain
unverified and must be done by the follow-up run after the §5 fix:

- Time-to-first-`/healthz`-200 and time-to-`healthy` (the
  start-period verdict); `docker inspect` health status.
- `GET /healthz`, `/readyz`, `/version`, `/v1/detectors` against the
  container, compared with worker 2's bare-server bodies
  (`{"status":"ok"}`, `{"status":"ready"}`,
  `{"name":"TextForensics","version":"0.2.0"}`, 1 detector
  `textforensics/builtin-heuristic` v`0.1.0`).
- `POST /v1/analyze` with worker 2's exact human paragraph (bare
  server: 200, score 0.1875, verdict `human_like_patterns`) and
  machine-like paragraph (bare server: 200, score 0.646, verdict
  `insufficient_evidence`) from
  `docs/live-host-api/req-human.json` / `req-machine.json`.
- `GET /` (bare server: 404 `{"detail":"Not Found"}` — expected
  identical from the container, API only).
- `POST /v1/analyze` with `{}` (bare server: 422) and with an
  oversized body (bare server: 413 for 2,000,001-byte text and for a
  body over the 4,065,536-byte middleware cap).
- `docker logs` verdict (zero errors/tracebacks — bare server was
  clean).
- Restart: `docker stop`, start again with the same command,
  `/healthz` answers again, health returns to healthy, with timings.

## 8. Branch verification (parent discipline)

- **Branch:** `fix/live-host-container`, head `884f590` + this file
  (docs only; no `src/`, no tests, no workflows, no
  `mutation-baseline.toml`, no `tests/test_mutation.py`, no
  `check_claims.py`, no `docs/validation/registry.json` touched).
- **pre-commit:** `pre-commit run --all-files`, **13/13 hooks passed,
  exit 0** on the transcript as first written (run twice; second run
  also 13/13, no files modified). After the claims-gate paragraph in
  this section was added, a final run shows **11 passed + 2 failed, both failures
  environmental**: `ruff (format)` fails writing its cache
  (`Operation not permitted` at `.ruff_cache/…`) and `detect-secrets`
  fails on the git `index.lock` write (same EPERM flakiness) — neither
  evaluates this document's content, and the hooks that do check the
  `.md` file (trailing-whitespace, end-of-file-fixer,
  mixed-line-ending, check-merge-conflict) passed in the final run.
- **Claims gate: NOT verifiable in this environment — see below.**
  Two runs of `scripts/check_claims.py --report-card
  /tmp/lh-claims-card.md` both produced the same outcome: **10 PASS /
  23 FAIL of 33 claims; registry 30 records, 30 valid.** Every one of
  the 23 FAILs is the identical environmental error, not a claim
  failure: the per-claim pytest subprocess crashes in
  `tempfile.gettempdir()` with `FileNotFoundError: No usable temporary
  directory found in ['/tmp', '/var/tmp', '/usr/tmp', ...]` — pytest
  cannot create temp files because this exec environment is
  intermittently denying data writes (`PermissionError: [Errno 1]
  Operation not permitted`) to non-shell processes. The 10 PASSes are
  the claims verified without pytest. The gate then also crashes
  writing the report card (same EPERM). This is **not a repo
  failure**: the branch adds one `.md` file, and the committed
  `docs/evidence/report-card.md` at this base records 33 passed, 0
  failed from a healthy run. **The parent must re-run the gate on the
  merged tree in a healthy environment.**
- **Side effect, repaired:** the first gate run (without
  `--report-card`, before the cause was understood) truncated
  `docs/evidence/report-card.md` to 0 bytes — `write_text` opens with
  truncate, then the data write failed with EPERM. The file was
  restored byte-identical to HEAD (5632 bytes; `git show HEAD:… |
  cmp - docs/evidence/report-card.md` exit 0). The second gate run
  used `--report-card /tmp/…` so the repo file was not touched again
  (re-verified intact afterwards, cmp exit 0).
- **Schemas:** `scripts/validate_schemas.py`, **12/12 OK, exit 0**.
- **Full suite:** not run by this worker — docs-only branch; the
  parent runs the suite on the merged tree (per the brief).

Environment note for the parent: the EPERM-on-write flakiness hit
this exec session throughout the verification step (roughly 19:55–
20:05 UTC): `python`, `git`, `cp`, `dd` data writes to regular files
failed intermittently with EPERM while shell builtins and reads kept
working, and `git` commands intermittently could not write
`index.lock`. Disk is not full (`/` 10% used, `/tmp` tmpfs 1% used).
It did not affect the container finding (§3–§4, recorded before the
flakiness started) or this document (written via the file tool, not
exec).
