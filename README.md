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

## 📄 License

Personal infrastructure project — free to use as reference.
