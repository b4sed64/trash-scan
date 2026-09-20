"""Favicon fingerprinting (httpx) and PTR-sweep of an approved CIDR (dnsx).

Both reuse requests/data the pipeline already makes — favicon hashing is one
extra lightweight GET per host (the same request a browser makes on every page
load), and the PTR sweep is pure DNS traffic against the resolver, never a
packet to the swept hosts themselves.
"""
from __future__ import annotations

import datetime as dt

import pytest

from app.adapters.base import StageInput
from app.adapters.fake import FakeDnsxAdapter
from app.adapters.httpx import _parse as httpx_parse
from app.models import PrivateCidr, ScanExecution, Target, User
from app.security import hash_password
from app.worker import runner

# --- favicon fingerprinting (httpx) -----------------------------------------


def _httpx_inp(hosts: list[str] | None = None) -> StageInput:
    return StageInput(stage="httpx", target_kind="CIDR", target_value="10.10.1.0/24",
                       profile="SAFE_ACTIVE", hosts=hosts or [], options={})


def test_httpx_parse_surfaces_favicon_hash_observation():
    line = '{"host":"10.10.1.5","url":"http://10.10.1.5","favicon":"147188781","favicon_md5":"x"}'
    observations, _ = httpx_parse([line], _httpx_inp())
    hits = [o for o in observations if o.kind == "TECH" and o.key == "favicon-hash"]
    assert len(hits) == 1
    assert hits[0].value == "147188781"
    assert hits[0].asset_value == "10.10.1.5"


def test_httpx_parse_omits_favicon_observation_when_hash_absent():
    line = '{"host":"10.10.1.5","url":"http://10.10.1.5","status_code":200}'
    observations, _ = httpx_parse([line], _httpx_inp())
    assert all(o.key != "favicon-hash" for o in observations)


# --- PTR sweep of a CIDR target (dnsx) --------------------------------------


def test_fake_dnsx_ptr_sweeps_a_cidr_range():
    inp = StageInput(stage="dnsx", target_kind="CIDR", target_value="10.10.1.0/24",
                     profile="PASSIVE", hosts=["10.10.1.1", "10.10.1.2", "10.10.1.3"], options={})
    out = FakeDnsxAdapter().run(inp)
    ptr_hosts = {o.asset_value for o in out.observations if o.key == "PTR"}
    # deterministic per-IP: about a third resolve to nothing, matching a real range
    assert ptr_hosts and ptr_hosts <= {"10.10.1.1", "10.10.1.2", "10.10.1.3"}
    for o in out.observations:
        if o.key == "PTR":
            assert o.value.startswith("host-")


@pytest.fixture
def cidr_lab(db):
    u = User(username="ptr_adm", role="ADMINISTRATOR", password_hash=hash_password("x" * 12),
             is_active=True)
    db.add_all([u, PrivateCidr(cidr="10.10.0.0/16")])
    t = Target(kind="CIDR", value="10.10.2.0/29")  # 6 usable hosts — small and fast
    db.add(t)
    db.flush()
    db.commit()
    return {"user": u.id, "target": t.id}


def test_passive_scan_of_a_cidr_surfaces_ptr_observations(db, cidr_lab):
    ex = ScanExecution(target_id=cidr_lab["target"], requested_by_id=cidr_lab["user"],
                       profile="PASSIVE", classification="PASSIVE", state="QUEUED",
                       queued_at=dt.datetime.now(dt.timezone.utc))
    db.add(ex)
    db.commit()
    assert runner.execute(ex.id) == "COMPLETED"
    db.expire_all()
    ex = db.get(ScanExecution, ex.id)
    dnsx_meta = next(s for s in ex.stages if s["stage"] == "dnsx")
    assert dnsx_meta["observations"] > 0
