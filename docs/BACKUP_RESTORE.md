# Database backup and restore

Trash Scan keeps all durable state in the `db_data` Docker volume (PostgreSQL). Generated
artifacts live in the `artifacts` volume. Automated backup orchestration is out of scope
for the MVP (PRD 19.1); this is the manual procedure.

## Back up

```sh
# Logical dump (portable, recommended)
docker compose exec -T db pg_dump -U trashscan trashscan > trashscan-$(date +%Y%m%d).sql

# Artifacts (reports, raw output) if present
docker run --rm -v trashscan_artifacts:/data -v "$PWD:/backup" alpine \
  tar czf /backup/trashscan-artifacts-$(date +%Y%m%d).tgz -C /data .
```

Store backups off the workstation. A dump contains scan results and target data — treat it
as sensitive. It does **not** contain plaintext passwords (Argon2id hashes only) but does
contain the audit chain.

## Restore

```sh
docker compose down
docker volume rm trashscan_db_data          # discard current state
docker compose up -d db
# wait for "database system is ready"
cat trashscan-YYYYMMDD.sql | docker compose exec -T db psql -U trashscan trashscan
docker compose up -d
```

## Verify after restore

1. Log in as an administrator.
2. Open **Audit trail → Verify chain now**. It must report "Chain intact".
3. Spot-check target and assignment counts.

## Notes

- The audit chain is tamper-evident, not tamper-proof: anyone who can write to the volume
  or a dump file can rewrite history. Verification only detects inconsistency, it cannot
  prove the current chain was never replaced wholesale.
- Migrations run automatically on API start (`alembic upgrade head`). Restoring an older
  dump and starting a newer image will apply pending migrations forward; the reverse is
  not supported.
