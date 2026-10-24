# TrueNAS SBOM Generator

A TrueNAS Community Edition (formerly SCALE) app that inventories the whole server on a schedule and reports known vulnerabilities. It's the same idea as the Unraid plugin, packaged as a custom app.

**Each scan produces**

| SBOM | How |
|---|---|
| `truenas-host` | Syft scan of the host root (mounted read-only). TrueNAS is Debian underneath, so Syft catalogs the OS packages natively and Grype matches them against Debian's security tracker, backported fixes included. Pools under `/mnt` are skipped. |
| `truenas-platform` | TrueNAS release and running kernel, with NVD CPEs. Syft can't name these on its own. |
| `container-<name>` | One SBOM per distinct image across all apps, stopped ones included. |

Grype then scans everything. Findings in CISA's Known Exploited list are tagged, and anything not in the previous run is marked new. A webhook (Discord or Slack-style) fires when something new shows up. SBOMs can also go to Dependency-Track for continuous monitoring.

The web UI (port 8099, password protected) shows the latest counts and run history, with **Scan now** and downloads for the report (Markdown), every finding (CSV), or the whole run (.tar.gz).

## Install

1. **Publish the image.** Push this folder to GitHub as `UnheardOTP/truenas-sbomgen`. The included workflow builds `ghcr.io/unheardotp/truenas-sbomgen` on every push and weekly, so the latest Syft, Grype and base-image patches get picked up. Make the package public under the repo's Packages settings, or add GHCR credentials in TrueNAS.
2. **Create a dataset** for results, for example `Media/apps/sbomgen`. The Grype database (several hundred MB) and image exports during scans live here.
3. In TrueNAS, go to **Apps → Discover Apps → ⋮ → Install via YAML**. Paste `compose.yaml` and change `UI_PASSWORD` and the dataset path.
4. Open `http://<truenas>:8099` and press **Scan now**. The first run downloads the vulnerability database, so it takes a few minutes.

Settings are environment variables in the YAML (schedule, scope, notifications, Dependency-Track). Change them under Apps → Edit. The page shows the active settings and the next scheduled run.

From a shell, `docker exec sbomgen python -m sbomgen scan` runs a scan with logs in your terminal.

## Security notes

- **Docker access goes through `docker-socket-proxy`**, which allows only read endpoints: listing containers and exporting images. It refuses all writes (`POST=0`), so the scanner can't start, stop or change anything. Never mount the raw Docker socket into the scanner itself; that's root on the host.
- The scanner runs with every Linux capability dropped except `DAC_READ_SEARCH` (read any file). It has a read-only root filesystem and `no-new-privileges`. The host is mounted read-only.
- The page and downloads require the UI password. A vulnerability inventory is a map for an attacker, so don't expose port 8099 outside your LAN. Put it behind your reverse proxy with auth if you need remote access.
- Syft and Grype are verified against their releases' SHA-256 checksums at image build.

## Limits

- If TrueNAS rejects mounting `/`, mount the parts Syft needs instead: `/etc`, `/usr`, `/var/lib/dpkg` and `/opt`, each under `/host/...`, read-only.
- Kernel findings come from the running kernel version. TrueNAS backports fixes, so check the release notes before acting on them.
- VMs and Incus instances aren't scanned. Run Syft inside them, or send their SBOMs to Dependency-Track.
- amd64 only.
