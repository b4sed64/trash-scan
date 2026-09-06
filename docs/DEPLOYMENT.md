# Deployment

Trash Scan is **self-hosted, one stack per machine**. There is no central server and no
SaaS. Everything runs from `docker-compose.yml`.

## 1. Run it locally (Docker Desktop on Windows/macOS)

```sh
git clone https://github.com/b4sed64/trash-scan.git
cd trash-scan
cp .env.example .env          # optional — edit POSTGRES_PASSWORD before anything real
docker compose up --build     # add -d to detach
```

Open <http://localhost:8080> and complete first-run administrator setup.

| Task | Command |
|---|---|
| Demo mode (fake scanners, no traffic) | `SCANNER_MODE=fake docker compose up -d --build` |
| Seed sample data | `RUN_SEED=1 docker compose up -d --build` |
| Stop | `docker compose down` |
| Stop and wipe all data | `docker compose down -v` |
| Follow logs | `docker compose logs -f api worker beat` |
| Update to latest code | `git pull && docker compose up -d --build` (migrations auto-apply) |
| Run tests | `docker build -t trashscan-api ./backend && docker run --rm trashscan-api pytest` |

Persistent state lives in two Docker volumes: `trashscan_db_data` (Postgres — accounts,
findings, audit chain) and `trashscan_artifacts` (raw scan output + generated reports).
Both survive `down`/`up` and code updates; only `down -v` deletes them.

## 2. Run it on another machine

### Same stack, different host (e.g. a Linux/Kali box in the lab)

- Install Docker Engine + the Compose plugin (or Docker Desktop). `git clone`, then the
  same `docker compose up --build`. The compose file is portable to Linux/Kali.
- **Data does not travel with the repo.** To migrate an existing deployment, use
  [`BACKUP_RESTORE.md`](BACKUP_RESTORE.md): `pg_dump` on the old host → `psql` on the new
  one, and copy the `artifacts` volume if you want old reports/raw output.
- On Linux, once the Phase 0 raw-packet spike is done, enable SYN/OS detection:

  ```yaml
  # docker-compose.yml — worker service
  worker:
    cap_add: ["NET_RAW"]        # minimum proven capability only
  ```

  and set `TRASHSCAN_ALLOW_RAW_PACKET=true`.

### Reach the dashboard from another machine on the LAN

The compose `ports:` already publish on all interfaces, so `http://<host-LAN-IP>:8080`
works immediately. **Before using that for anything real, put TLS in front** — the PRD
requires encryption beyond localhost.

Minimal example with [Caddy](https://caddyserver.com/) as a TLS-terminating reverse proxy
on the same host (Caddy gets a cert automatically for a real hostname, or use its internal
CA for a lab):

```
# Caddyfile
trashscan.lab.example.com {
    reverse_proxy localhost:8080
}
```

Then in `.env`:

```
TRASHSCAN_SESSION_COOKIE_SECURE=true
TRASHSCAN_FRONTEND_ORIGIN=https://trashscan.lab.example.com
```

and restart: `docker compose up -d`. (Set `session_cookie_secure=true` only once TLS is in
front — Secure cookies are dropped over plain HTTP.)

### Worker reachability to the lab

The `worker` container must have network routes to the virtual lab segments it scans.
Docker Desktop + WSL networking, NAT and the Windows Firewall all affect this — validate it
during the Phase 0 spike and record the supported topology. Report uncertainty rather than
treating a missing response as proof that an asset does not exist.

## 3. Backup & restore

See [`BACKUP_RESTORE.md`](BACKUP_RESTORE.md). After any restore, log in and run
**Audit trail → Verify chain now** — it must report "Chain intact".

## 4. What is NOT included

Automated backup orchestration, HTTPS certificate management, host hardening, and
lab-network configuration are out of scope for the MVP and are the operator's
responsibility.
