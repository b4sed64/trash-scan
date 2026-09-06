"""Optional development seed data.

Run inside the API container:  ``python -m app.seed``

Creates a private CIDR, one scanner account and one internal target, all wired
through the same services the API uses. Safe to run repeatedly.
"""
from __future__ import annotations

import os

from sqlalchemy import select

from .db import SessionLocal
from .models import Assignment, PrivateCidr, Target, User
from .security import hash_password
from .services import AuditService, canonicalize_target

ADMIN_USER = os.getenv("TRASHSCAN_SEED_ADMIN", "admin")
ADMIN_PASS = os.getenv("TRASHSCAN_SEED_ADMIN_PASSWORD", "change-me-admin-123")
SCANNER_USER = os.getenv("TRASHSCAN_SEED_SCANNER", "scanner")
SCANNER_PASS = os.getenv("TRASHSCAN_SEED_SCANNER_PASSWORD", "change-me-scanner-123")
LAB_CIDR = os.getenv("TRASHSCAN_SEED_CIDR", "10.10.0.0/16")
LAB_TARGET = os.getenv("TRASHSCAN_SEED_TARGET", "10.10.5.20")


def main() -> None:
    with SessionLocal() as db:
        admin = db.execute(select(User).where(User.username == ADMIN_USER)).scalar_one_or_none()
        if admin is None:
            admin = User(
                username=ADMIN_USER, role="ADMINISTRATOR",
                password_hash=hash_password(ADMIN_PASS), is_active=True,
            )
            db.add(admin)
            db.flush()
            AuditService.append(
                db, actor="system:seed", action="ACCOUNT_CREATED",
                object_type="user", object_id=admin.id, payload={"role": "ADMINISTRATOR"},
            )

        scanner = db.execute(
            select(User).where(User.username == SCANNER_USER)
        ).scalar_one_or_none()
        if scanner is None:
            scanner = User(
                username=SCANNER_USER, role="SCANNER",
                password_hash=hash_password(SCANNER_PASS), is_active=True,
            )
            db.add(scanner)
            db.flush()
            AuditService.append(
                db, actor="system:seed", action="ACCOUNT_CREATED",
                object_type="user", object_id=scanner.id, payload={"role": "SCANNER"},
            )

        if not db.execute(select(PrivateCidr).where(PrivateCidr.cidr == LAB_CIDR)).scalar_one_or_none():
            cidr = PrivateCidr(cidr=LAB_CIDR, note="seed lab range", created_by_id=admin.id)
            db.add(cidr)
            db.flush()
            AuditService.append(
                db, actor="system:seed", action="PRIVATE_SCOPE_ADDED",
                object_type="private_cidr", object_id=cidr.id, payload={"cidr": LAB_CIDR},
            )

        kind, canonical = canonicalize_target(LAB_TARGET)
        target = db.execute(
            select(Target).where(Target.kind == kind, Target.value == canonical)
        ).scalar_one_or_none()
        if target is None:
            target = Target(kind=kind, value=canonical, note="seed target", created_by_id=admin.id)
            db.add(target)
            db.flush()
            AuditService.append(
                db, actor="system:seed", action="TARGET_CREATED",
                object_type="target", object_id=target.id,
                payload={"kind": kind, "value": canonical, "is_public": False},
            )

        if not db.execute(
            select(Assignment).where(
                Assignment.target_id == target.id, Assignment.user_id == scanner.id
            )
        ).scalar_one_or_none():
            db.add(Assignment(target_id=target.id, user_id=scanner.id, created_by_id=admin.id))
            AuditService.append(
                db, actor="system:seed", action="ASSIGNMENT_CREATED",
                object_type="target", object_id=target.id, payload={"user_id": scanner.id},
            )

        db.commit()
        print(f"Seed complete. admin={ADMIN_USER} scanner={SCANNER_USER} target={canonical}")


if __name__ == "__main__":
    main()
