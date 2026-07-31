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
- **Traceable Cloudflare Access logins (optional):** polls the official Zero Trust Access authentication-log API and reports identity, the public client IP observed by Cloudflare, application and Ray ID. For SSH/TCP, where the origin can only see the `cloudflared` process address, a local SSH login is explicitly marked as a time-based correlation with the latest allowed Access event.
- **Private GeoIP enrichment:** Access, SSH brute-force and Fail2ban alerts include the country estimated from the public IP. A country supplied by Cloudflare is preferred; otherwise Centinela reads a local Country MMDB (DB-IP Lite or MaxMind GeoLite2) and caches results. Client IPs are never sent to a third-party geolocation API. Country is context, not proof of physical location: VPNs, proxies and mobile/CGNAT networks may report their exit country.

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
| `FAIL2BAN_ENABLED` | Notify new bans (client status with journald fallback) |
| `CLOUDFLARE_ACCOUNT_ID` / `CLOUDFLARE_ACCESS_TOKEN` | Optional Access authentication logs (`Access: Audit Logs Read`) |
| `CLOUDFLARE_ACCESS_APP` / `CLOUDFLARE_CORRELATION_SECONDS` | Limit Access events to one app and bound SSH correlation |
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

## 📄 License

Personal infrastructure project — free to use as reference.
