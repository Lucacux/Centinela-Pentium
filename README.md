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
- **Private GeoIP enrichment:** Access, SSH brute-force and Fail2ban alerts include the country estimated from the public IP. A country supplied by Cloudflare is preferred; otherwise Centinela reads a local MaxMind GeoLite2 Country database and caches results. Client IPs are never sent to a third-party geolocation API. Country is context, not proof of physical location: VPNs, proxies and mobile/CGNAT networks may report their exit country.

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

1. Create a MaxMind GeoLite account and generate a download license key.
2. Install `geoipupdate` on the server and configure `EditionIDs GeoLite2-Country`
   in its `GeoIP.conf`. Keep the account ID and license key outside this repo.
3. Run `geoipupdate` and point `GEOIP_COUNTRY_DB` at the generated
   `GeoLite2-Country.mmdb`. The bot also discovers the usual Linux locations
   under `/var/lib/GeoIP`, `/usr/share/GeoIP`, and `/usr/local/share/GeoIP`.
4. Schedule `geoipupdate` with its distro-provided timer or cron job so country
   estimates do not become stale.

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
| `GEOIP_COUNTRY_DB` / `GEOIP_COUNTRY_LOCALE` | Local `GeoLite2-Country.mmdb` path and preferred country-name language |
| `SWAP_ALERT_PCT` / `TEMP_ALERT_C` | Resource alert thresholds |
| `GRAFANA_URL` / `GRAFANA_TOKEN` | Grafana API URL and Viewer service-account token |
| `GRAFANA_GUARDIAN_*` | Fleet panel, range, dimensions, and enable/disable switch for Guardian Report |

## 📄 License

Personal infrastructure project — free to use as reference.
