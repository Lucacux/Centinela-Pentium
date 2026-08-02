# 🛡️ Centinela

![Centinela Banner](./assets/banner.png)

A Discord bot for monitoring and securing Linux servers (multi-distro: Arch / Debian-Ubuntu), running 24/7 as an infrastructure watchdog for a personal homelab.

## ✨ Key Features

- **Multi-distro SSH Watcher:** detects SSH logins and authentication failures in real time, using `journalctl` (Arch) or parsing `/var/log/auth.log` (Debian/Ubuntu) depending on the host.
- **Brute Force Detection:** tracks failed SSH attempts within a configurable time window and fires an alert once a threshold is crossed, with a cooldown to avoid alert spam.
- **Service Monitoring:** checks the status of managed systemd services (`systemctl is-active`) and reports outages.
- **Resource Alerts:** configurable thresholds for swap usage and system temperature.
- **Security Score:** aggregates SSH events, service failures, and other metrics into a single health score.
- **Charts:** generates visual charts of system status via [QuickChart](https://quickchart.io/).
- **Swarm-aware container view (`!ct`):** groups containers by *service*, not by task. Under Docker Swarm a container is named `<service>.<slot>.<taskid>` and the task id is regenerated on every redeploy, so raw names are unreadable, impossible to type, and each redeploy leaves the previous task behind as `Exited` — a healthy service looks like one green container next to one red one. `!ct` collapses that into a single entry per service and notes how many stale tasks were left over.
- **Correct restarts under Swarm:** `!restart <service>` issues `docker service update --force` for Swarm services and falls back to `docker restart` for plain containers. A plain `docker restart` on a Swarm task is the wrong operation — the orchestrator just recreates the task on its own, outside the scheduler.
- **Update Commands:** suggests the correct update command (`pacman -Syu` / `apt upgrade`) based on the detected distro.
- **Grafana Panels (optional):** view your *actual* Grafana dashboard panels inside Discord. Dashboards and panels are discovered **dynamically** via the Grafana API — add a dashboard or panel in Grafana and it shows up in the bot with **zero code changes**. Panels are rendered server-side by Grafana (requires the [`grafana-image-renderer`](https://grafana.com/grafana/plugins/grafana-image-renderer/) plugin), so the image is pixel-identical to the dashboard.
- **Complete Fleet Overview in Guardian Report:** every six hours the bot renders the full Grafana dashboard (summary, node table, CPU, RAM, disk, load, network and temperatures) and splits the tall PNG into readable Discord pages. Dashboard, range, render dimensions and page height are configurable through `GRAFANA_GUARDIAN_*`.
- **Correlated security events:** SSH failures are grouped by source IP and users attempted; a Fail2ban ban is enriched with those preceding attempts. The watcher uses `fail2ban-client` when permitted and falls back to the read-only Fail2ban journal.
- **Traceable Cloudflare Access logins (optional):** polls the official Zero Trust Access authentication-log API and reports identity, the public client IP observed by Cloudflare, application and Ray ID. For SSH/TCP, where the origin can only see the `cloudflared` process address, a loopback SSH login triggers an immediate API refresh with short retries. Centinela then claims the closest allowed event for the exact configured application, so one Access event cannot enrich two SSH sessions. If the API is unavailable or there is no match, the alert keeps the observed loopback address rather than guessing.
- **Private GeoIP enrichment:** Access, SSH brute-force and Fail2ban alerts include the country estimated from the public IP. A country supplied by Cloudflare is preferred; otherwise Centinela reads a local Country MMDB (DB-IP Lite or MaxMind GeoLite2) and caches results. Client IPs are never sent to a third-party geolocation API. Country is context, not proof of physical location: VPNs, proxies and mobile/CGNAT networks may report their exit country.
- **One bot for Pentium + Arch:** the Discord bot runs only on Pentium and also
  monitors `server-mbp` through a constrained collector. The collector key has
  `restrict` plus an OpenSSH forced command: it cannot start a shell, forward
  ports or execute arbitrary commands. Metrics, temperatures, services,
  sessions, ports, Docker, backups, SSH/fail2ban events and allowed restarts are
  exposed as typed JSON operations.
- **Container + native-service endpoints in Grafana:** a read-only local
  discovery timer exports published container ports, container-network
  endpoints and listening systemd services as
  `centinela_runtime_endpoint_info`. The `Contenedores + servicios` dashboard
  shows host, runtime, service, IP, port, protocol, endpoint and exposure scope.
  Wildcard binds are rendered with the host's real LAN address; localhost stays
  explicitly marked local.

### 🛰 Unified Arch node

The old Arch Discord process is not needed. Once the central node is configured,
the same bot exposes both command styles:

```
!arch                         # remote status
!arch help                    # complete remote command list
!arch ct                      # containers, published IP/ports and resources
!arch logs truly-api
!arch restart truly-api       # only names in the remote allowlist

!status arch                  # equivalent suffix form
!temps arch
!logs truly-api arch
```

Four central loops supervise the remote node: resource/service/network state,
SSH and Fail2ban correlation, Docker resource/loop recovery, and Borg freshness.
Each has independent history, deduplication and cooldown state, so an event on
Arch cannot inflate or suppress a Pentium alert. Country lookup remains local.

The remote side is installed with
`deploy/install-remote-agent.sh`, using
`deploy/centinela-agent.json.example` as the explicit service/restart policy.
`deploy/configure-remote-env.py` updates only the allowlisted `REMOTE_ARCH_*`
keys atomically and never prints or rewrites Discord/Cloudflare secrets.

Endpoint inventory uses `runtime_discovery.py` and the units under `deploy/`.
It reads Docker metadata, listening sockets and `/proc` cgroups as a oneshot
root service, writes only one atomic Prometheus textfile, and is sandboxed by
systemd. `deploy/update-grafana-runtime-panel.py` backs up both affected
dashboards before applying the idempotent panel/link update.

### 🤝 Split with the Updates-Bot

Both bots post to the same Discord channel, so the command namespace is shared and
overlapping names mean two bots answering the same message. The split:

| Scope | Owner |
|---|---|
| Live container state, logs, restarts, systemd services, host metrics | **Centinela** (`!ct`, `!logs`, `!restart`, `!services`, `!status`) |
| Docker **image** updates across the fleet | **Updates-Bot** (`!docker status`, `!docker fix`) |
| CVEs across the fleet | **Updates-Bot** (`!cve status`, `!cve host <node>`) |

`!docker` and `!cve` used to exist here too and were removed, not renamed away for
cosmetics: the Updates-Bot separates *"a fix was published"* from *"an update
actually closes it"*. The raw `debsecan`/`arch-audit` output this bot used to print
does not make that distinction, so it reported dozens of permanently-unfixable
Critical findings — which trains you to ignore the colour red.

### 📊 Grafana command

```
!grafana                      # list dashboards (by folder)
!grafana <dashboard>          # list that dashboard's panels
!grafana <dashboard> <panel>  # render one panel as the exact Grafana image
!grafana <dashboard> <panel> 24h   # ...over a custom time range (15m|6h|24h|7d)
!grafana <dashboard> full     # render the whole dashboard in one image
```

`<dashboard>` matches by uid or by a substring of the title; `<panel>` by id or title substring. Enable it by setting `GRAFANA_URL` and `GRAFANA_TOKEN` (a Grafana service-account token, Viewer role is enough) in `.env`.

The periodic Guardian report waits five minutes after a bot restart before its
first Fleet Overview render.  This prevents deployments from competing with a
cold image renderer; tune it with `GRAFANA_GUARDIAN_START_DELAY_SECONDS`.

### 🌐 Network diagnostics

`!red` (aliases `!net`, `!diag`) replaces the old boolean "internet is down" check
with a layered diagnosis that names the **first layer that broke**, because the
four failure modes it used to collapse into one are not fixed the same way:

| Layer | Question it answers |
|---|---|
| `enlace` | Is the local link/gateway alive? *(the problem is inside the house)* |
| `wan` | Is there egress to the internet, without DNS involved? |
| `dns` | Do names resolve — via the local resolver *and* an external one? |
| `http` | Does real HTTPS traffic get through, or is it a captive portal / DPI? |
| `onu` | Is the fiber ONU alive? *(read from the ISP Uplink Guardian)* |

Two details this depends on, both verified on the host:

- **The gateway drops ICMP.** Pinging `192.168.2.1` returns 100% packet loss with
  the internet working perfectly, so the link layer is confirmed via ARP
  reachability and TCP first, and only falls back to ping. Basing this layer on
  ping alone reports a permanently dead link.
- **The configured resolver *is* the gateway**, so DNS and gateway fail together
  and are indistinguishable unless resolution is also tested against an external
  resolver. That contrast is what separates "my resolver broke" from "there is no
  DNS anywhere".

The ONU layer is **read-only**: the Centinela never triggers a reboot. That stays
with the [ISP Uplink Guardian](https://github.com/Lucacux/isp-uplink-guardian),
which is queried through its `/api/status` endpoint — that is also where the
outage history shown under "Últimos cortes" comes from.

### 📡 Speedtest

`!speedtest` (alias `!velocidad`) measures the link and compares it against your
own rolling median rather than a fixed threshold, and `watch_speed` builds that
baseline every `SPEEDTEST_EVERY_HOURS`.

**Pin `SPEEDTEST_SERVER_ID`.** Auto-selection on this connection returns servers
in Brazil ~3400 km away and can pick a different one each run, so the number ends
up dominated by international transit; unpinned, any "slow internet" threshold
produces false positives. `speedtest-cli --list` shows the available IDs. Each run
costs ~40 MB and ~25 s, hence the cooldown, and measurements are skipped entirely
while the network is unhealthy so a broken link cannot poison the baseline.

### 🚨 Alarms

Threshold alerting is a small CloudWatch-style engine (`alerts.py`) instead of
hand-written `if value > threshold and cooldown` blocks. `!alarmas` shows the
current state of every alarm.

| What it fixes | Before | Now |
|---|---|---|
| Single-sample triggers | One 91% disk sample sent `DISCO CRITICO` | **N of M datapoints** — 2 of 3 by default |
| No recovery notice | `CPU CRITICA` arrived, `normalizada` never did | Every state transition notifies, with how long it lasted |
| Unmeasurable = fine | A vanished sensor read as 0 and looked healthy | Explicit `INSUFFICIENT_DATA` state |
| Cooldown hid transitions | The 1h cooldown swallowed the recovery message | Cooldown applies only to reminders, never to transitions |

**Quiet hours**: at night only `critica` alarms get through. Recoveries are held
too — waking someone to say something already fixed itself is the worst possible
alert.

**Actions are proposed, never executed.** Each alarm carries a suggested next
step that is posted with the alert; the bot does not act on the system by itself.
Auto-execution exists (`auto=True`) but is off for every alarm and has to be
turned on deliberately, one alarm at a time.

### 📊 Process sampling

`procmon.py` exists because the high-consumption diagnosis was silently broken.
`psutil.Process.cpu_percent()` without an interval returns usage *since the
previous call on that same object* — the first call always returns `0.0`. `!top`
got away with it by priming and sleeping 1s, but `watch_resources` called it
cold, so the CPU alert — the one moment the information matters — listed
`systemd`, `kthreadd` and `kworker` at 0%, ordered by PID.

The fix keeps the `Process` objects alive between samples and refreshes them from
the one-minute loop, so each reading is a true one-minute average and alerts read
warm data without sleeping or blocking the event loop. CPU is normalised by core
count (psutil reports up to `100 * ncores`, i.e. 200% on the E5400).

**On the remote node** the same guarantee needs a different mechanism: the agent
is a one-shot process per SSH connection, so every `cpu_percent()` there would be
a first call and return `0.0`. It keeps the cumulative CPU times of the previous
poll in a small state file under `/run` and reports the delta, which makes each
reading a true average over the polling interval without sleeping inside the
agent. The top consumers travel *inside* `snapshot`, not as a second request
after an alarm fires — the culprit has to be the one measured during the breach,
not whatever the machine is doing once it has calmed down. Processes owned by a
container are reported by container name rather than by `python3`.

### 🔐 SSH key identity

sshd writes the fingerprint of the accepted key on every login at `LogLevel INFO`
(`Accepted publickey for luca from 192.168.2.40 port 55160 ssh2: ED25519
SHA256:...`); `VERBOSE` is not required. That fingerprint is the only thing in
the log that separates two automations sharing one Unix account — the user and
the source IP are identical, the key is not.

Fingerprints are resolved to names through the `authorized_keys` of the node:
the agent publishes `ssh-keygen -lf` output (fingerprints and comments only, no
key material), and `SSH_KEY_LABELS` overrides the comment where it is not
descriptive enough.

Two failure modes are kept distinct on purpose. A fingerprint missing from a
keyring the bot *could* read means sshd accepted a key nobody can account for,
and that is a real alert. A fingerprint whose keyring the bot could *not* read
(`/root/.ssh/authorized_keys` is mode 600) is reported as unverifiable instead —
claiming "unrecognized key" on every nightly deploy would train the alert to be
ignored.

### 🕵️ Anomalous logins

`ssh_baseline.py` keeps a persistent profile per `(node, fingerprint, user)`:
usual source subnet, hour histogram and auth method. The in-memory correlator
only spans 900 seconds, which is enough to tie a fail2ban ban to the failures
that caused it but cannot answer "has this key ever logged in before".

Signals, strongest first: unknown fingerprint · password auth on a keys-only
host · key authorized for one account used on another · new source subnet (with
an external IP outranking a LAN one) · login outside the key's usual schedule.

The schedule signal only fires for keys that *have* a schedule — a deploy
controller that always runs at 20:50 spans one hour bucket, an interactive key
spans many and is never flagged for the hour. Profiles younger than five logins
produce no anomalies at all: "I have never seen this" means nothing without
history behind it.

### ⚠️ Failed logins

Below the brute-force threshold, failures are now reported individually with a
per-IP cooldown. sshd distinguishes `Invalid user` (the account does not exist —
generic Internet scanning, reported grey) from a failure against a real account
(someone knows who to aim at, reported orange). Account enumeration produces no
`Failed` line at all, so `Invalid user` and `[preauth]` disconnects are collected
too.

## 🧰 Stack

- Python 3.12
- [discord.py](https://github.com/Rapptz/discord.py) 2.7
- `psutil` for system metrics
- `python-dotenv` for configuration

## 🚀 Installation

```bash
git clone https://github.com/Lucacux/Centinela-Pentium.git
cd Centinela-Pentium
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env  # fill in your real values
python main.py
```

### systemd hardening

Production runs the bot as the dedicated `centinela` system account, not as an
interactive administrator. The audited drop-in is
`deploy/discord-bot-hardening.conf`; install it as
`/etc/systemd/system/discord-bot.service.d/hardening.conf` only after moving
writable state to `/var/lib/centinela` and any constrained remote-agent key to
`/etc/centinela`. The account needs `adm` to read SSH/journal events and,
currently, `docker` for container inspection and explicitly requested
restarts. It must not belong to `sudo` or `lxd`.

Because `ProtectHome=yes` empties `/home` for the service, the `authorized_keys`
that feed the fingerprint-to-identity map have to be re-exposed one file at a
time through the `BindReadOnlyPaths=` lines in the drop-in, matching
`SSH_KEY_DIRECTORY_FILES`. These are public keys and the fingerprint already
reaches the journal on every login; what is not granted is the `.ssh` directory
itself. `BindReadOnlyPaths` only makes the file visible — Unix permissions still
apply, so a root-owned `authorized_keys` also needs
`setfacl -m u:centinela:r /root/.ssh/authorized_keys` to be readable. Without
it the bot degrades honestly and reports root logins as unverifiable rather
than unrecognized.

The drop-in makes the OS, home directories, kernel interfaces and namespaces
read-only or inaccessible, removes every process capability and enables
`NoNewPrivileges`. Validate with `systemd-analyze verify discord-bot.service`,
then restart and confirm `systemd-analyze security discord-bot.service` plus
the Discord gateway log. Docker group membership remains a root-equivalent
trust boundary; the next hardening stage is replacing it with a narrow helper.

### Local GeoIP country database

The production setup uses the monthly
[DB-IP Country Lite](https://db-ip.com/db/download/ip-to-country-lite) MMDB,
licensed under CC BY 4.0. Its source is attributed in every Discord field that
uses it. `deploy/centinela-geoip-update.sh` downloads and validates the latest
available monthly database without sending client IPs anywhere.

MaxMind GeoLite2 Country is also supported. Point `GEOIP_COUNTRY_DB` at either
compatible MMDB; the bot additionally discovers `Country.mmdb` and
`GeoLite2-Country.mmdb` under the usual `/var/lib/GeoIP`, `/usr/share/GeoIP`,
and `/usr/local/share/GeoIP` paths.

If the database is absent, corrupt, or cannot resolve an address, security
monitoring continues normally and simply omits the country field.

## ⚙️ Environment Variables

See [`.env.example`](./.env.example) for the full list:

| Variable | Description |
|---|---|
| `DISCORD_TOKEN` | Discord bot token |
| `DISCORD_CHANNEL_ID` | Channel where alerts are posted |
| `SERVER_NAME` | Identifier name for the monitored server |
| `SAFE_SUBNETS` | Subnets considered "trusted" for SSH logins |
| `WATCHED_SERVICES` / `MANAGED_SERVICES` | systemd services under supervision |
| `ALLOWED_RESTART` | Services the bot is allowed to restart |
| `SSH_FAIL_THRESHOLD` / `SSH_FAIL_WINDOW` | Threshold and window for brute-force detection |
| `SSH_FAIL_NOTIFY_ENABLED` / `SSH_FAIL_NOTIFY_COOLDOWN_MIN` | Report failures *below* the brute-force threshold, rate-limited per IP |
| `SSH_KEY_DIRECTORY_FILES` | `authorized_keys` to read as `user:/path`; needs a matching `BindReadOnlyPaths` under the hardening drop-in |
| `SSH_KEY_LABELS` / `REMOTE_ARCH_SSH_KEY_LABELS` | `FINGERPRINT=Name` overrides, for when the key comment is not descriptive |
| `SSH_KEY_REFRESH_MINUTES` | How often the key directories are re-read, so a new key does not need a bot restart |
| `SSH_ANOMALY_ENABLED` / `SSH_BASELINE_PATH` | Anomalous-login detection and where its persistent profiles live |
| `FAIL2BAN_ENABLED` | Notify new bans (client status with journald fallback) |
| `CLOUDFLARE_ACCOUNT_ID` / `CLOUDFLARE_ACCESS_TOKEN` | Optional Access authentication logs; use an account-scoped token with only `Access: Audit Logs Read` |
| `CLOUDFLARE_ACCESS_APP` / `CLOUDFLARE_CORRELATION_SECONDS` | Exact Access hostname (optionally URL/path) and maximum clock/time skew used for SSH correlation |
| `GEOIP_COUNTRY_DB` / `GEOIP_COUNTRY_LOCALE` | Local Country MMDB path and preferred country-name language |
| `SWAP_ALERT_PCT` / `TEMP_ALERT_C` | Resource alert thresholds |
| `GRAFANA_URL` / `GRAFANA_TOKEN` | Grafana API URL and Viewer service-account token |
| `GRAFANA_GUARDIAN_*` | Fleet panel, range, dimensions, and enable/disable switch for Guardian Report |
| `ISP_GUARDIAN_URL` | ISP Uplink Guardian API, read-only. Empty = ONU layer skipped, everything else still works |
| `NET_DNS_PROBE` / `NET_DNS_EXTERNAL` | Name to resolve, and the contrast resolver that isolates a broken local DNS |
| `NET_WAN_IPS` / `NET_GATEWAY_PORTS` | WAN probe targets, and gateway ports used because it filters ICMP |
| `NET_HTTP_PROBE` / `NET_HTTP_EXPECT` | Captive-portal probe URL and its expected status code |
| `SPEEDTEST_SERVER_ID` | **Pin this.** Auto-selection picks servers 3400 km away and varies per run |
| `SPEEDTEST_ENABLED` / `SPEEDTEST_EVERY_HOURS` / `SPEEDTEST_COOLDOWN_MIN` | Periodic measurement and rate limiting |
| `SPEEDTEST_SLOW_RATIO` / `SPEEDTEST_DEGRADED_RATIO` | Thresholds as a fraction of your median. Loose on purpose: this link swings 26% between back-to-back runs |
| `QUIET_HOURS_ENABLED` / `QUIET_HOURS_START` / `QUIET_HOURS_END` | Night window where only critical alarms notify |
| `REMOTE_ARCH_*` | Optional constrained SSH collector for the unified Arch node: address, identity, host-key file and independent alarm/security thresholds |

## 📄 License

Personal infrastructure project — free to use as reference.
