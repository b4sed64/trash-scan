"""ProjectDiscovery katana adapter — bounded crawling feeding Nuclei.

``_parse`` is tested directly against katana's real JSONL shape (the crawled
URL nests under ``request.endpoint``; there is no top-level host field). The
rest is exercised end to end through the fake pipeline: katana's discoveries
must reach the Nuclei stage that runs after it, within the same execution.
"""
from __future__ import annotations

import datetime as dt

import pytest

from app.adapters.base import StageInput
from app.adapters.katana import _parse
from app.models import Finding, PrivateCidr, ScanExecution, Service, Target, User
from app.scan_profiles import PROFILES
from app.security import hash_password
from app.worker import runner

KATANA_ROW = (
    '{"timestamp":"2026-01-01T00:00:00Z",'
    '"request":{"method":"GET","endpoint":"http://10.10.5.20/admin/login","source":"body"},'
    '"response":{"status_code":200}}'
)


def test_parse_extracts_endpoint_and_derives_host_from_the_url():
    out = _parse([KATANA_ROW])
    assert len(out) == 1
    assert out[0].kind == "TECH" and out[0].key == "endpoint"
    assert out[0].value == "http://10.10.5.20/admin/login"
    assert out[0].asset_value == "10.10.5.20"
    assert out[0].source == "katana"


def test_parse_dedupes_repeated_endpoints_and_skips_garbage():
    lines = [KATANA_ROW, KATANA_ROW, "not json", "{}", '{"request": {}}']
    out = _parse(lines)
    assert len(out) == 1


def test_katana_only_in_active_profiles():
    assert "katana" not in PROFILES["PASSIVE"].stages
    assert "katana" in PROFILES["SAFE_ACTIVE"].stages
    assert "katana" in PROFILES["STANDARD_ACTIVE"].stages
    # positioned after httpx and before nuclei so discoveries reach Nuclei
    stages = PROFILES["SAFE_ACTIVE"].stages
    assert stages.index("httpx") < stages.index("katana") < stages.index("nuclei")


# --- end-to-end through the fake pipeline --------------------------------


@pytest.fixture
def lab(db):
    u = User(username="katana_adm", role="ADMINISTRATOR", password_hash=hash_password("x" * 12),
             is_active=True)
    db.add_all([u, PrivateCidr(cidr="10.10.0.0/16")])
    t = Target(kind="IPV4", value="10.10.5.20")
    db.add(t)
    db.flush()
    db.commit()
    return {"user": u.id, "target": t.id}


def _run_active(db, target_id, user_id) -> str:
    ex = ScanExecution(target_id=target_id, requested_by_id=user_id, profile="SAFE_ACTIVE",
                       classification="ACTIVE", state="QUEUED",
                       queued_at=dt.datetime.now(dt.timezone.utc),
                       approval_expires_at=dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=2))
    db.add(ex)
    db.commit()
    assert runner.execute(ex.id) == "COMPLETED"
    return ex.id


def test_katanas_discoveries_are_visible_on_the_execution(db, lab):
    ex_id = _run_active(db, lab["target"], lab["user"])
    db.expire_all()
    ex = db.get(ScanExecution, ex_id)
    katana_meta = next(m for m in ex.stages if m["stage"] == "katana")
    assert katana_meta["ok"] is True
    assert katana_meta["observations"] > 0
    # sanity: the rest of the pipeline still ran fine around the new stage
    assert db.query(Service).filter(Service.target_id == lab["target"]).count() > 0
    assert db.query(Finding).filter(Finding.target_id == lab["target"]).count() > 0
