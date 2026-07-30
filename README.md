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
- **Vulnerability Auditing:** integrates `arch-audit` (Arch) or `debsecan` (Debian/Ubuntu) to report packages with known CVEs.
- **Update Commands:** suggests the correct update command (`pacman -Syu` / `apt upgrade`) based on the detected distro.
- **Grafana Panels (optional):** view your *actual* Grafana dashboard panels inside Discord. Dashboards and panels are discovered **dynamically** via the Grafana API — add a dashboard or panel in Grafana and it shows up in the bot with **zero code changes**. Panels are rendered server-side by Grafana (requires the [`grafana-image-renderer`](https://grafana.com/grafana/plugins/grafana-image-renderer/) plugin), so the image is pixel-identical to the dashboard.
- **Fleet snapshot in Guardian Report:** when Grafana is configured, every six-hour Guardian Report includes the `Estado de nodos` panel from `Fleet Overview` in the same Discord message. Dashboard, panel, range, and image dimensions can be changed through the `GRAFANA_GUARDIAN_*` variables.

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
| `SWAP_ALERT_PCT` / `TEMP_ALERT_C` | Resource alert thresholds |
| `GRAFANA_URL` / `GRAFANA_TOKEN` | Grafana API URL and Viewer service-account token |
| `GRAFANA_GUARDIAN_*` | Fleet panel, range, dimensions, and enable/disable switch for Guardian Report |

## 📄 License

Personal infrastructure project — free to use as reference.
