"""Tool & template maintenance workflow (PRD §12.6).

The application never updates tools or templates itself. This surface records the
current pinned versions and the reviewed template set, lets an administrator
propose a change, and captures the review decision in the permanent audit chain.
Applying a change is a controlled image rebuild performed by an operator.
"""
from __future__ import annotations

import datetime as dt

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..adapters.base import STAGE_DNSX, STAGE_HTTPX, STAGE_NMAP, STAGE_NUCLEI, STAGE_SUBFINDER
from ..adapters.nuclei import TEMPLATE_DIR, template_set_hash, verify_template_set
from ..adapters.registry import get_adapter
from ..db import get_db
from ..models import MaintenanceProposal, Notification, User
from ..services import AuditService
from .deps import require_admin, require_csrf

router = APIRouter(prefix="/api/admin/maintenance", tags=["maintenance"],
                   dependencies=[Depends(require_admin)])

_TOOL_STAGES = [STAGE_SUBFINDER, STAGE_DNSX, STAGE_NMAP, STAGE_HTTPX, STAGE_NUCLEI]


class ProposalCreate(BaseModel):
    note: str = Field(min_length=1, max_length=4000)
    proposed_tool_versions: dict[str, str] = Field(default_factory=dict)
    proposed_template_note: str = Field(default="", max_length=4000)


class Decision(BaseModel):
    decision_note: str = Field(default="", max_length=4000)


def _current_state(db: Session) -> dict:
    ok, hashes, reason = verify_template_set()
    return {
        "tool_versions": {stage: get_adapter(stage).tool_version() for stage in _TOOL_STAGES},
        "template_dir": str(TEMPLATE_DIR),
        "template_set_ok": ok,
        "template_set_reason": reason,
        "template_set_hash": template_set_hash(),
        "templates": hashes,
    }


def _proposal_dto(p: MaintenanceProposal) -> dict:
    return {
        "id": p.id, "state": p.state, "note": p.note,
        "current_state": p.current_state, "proposed_state": p.proposed_state,
        "created_by_id": p.created_by_id, "created_at": p.created_at,
        "decided_by_id": p.decided_by_id, "decided_at": p.decided_at,
        "decision_note": p.decision_note,
    }


@router.get("")
def get_maintenance(db: Session = Depends(get_db)) -> dict:
    proposals = db.execute(
        select(MaintenanceProposal).order_by(MaintenanceProposal.created_at.desc()).limit(50)
    ).scalars().all()
    return {"current": _current_state(db), "proposals": [_proposal_dto(p) for p in proposals]}


@router.post("/proposals", status_code=status.HTTP_201_CREATED,
             dependencies=[Depends(require_csrf)])
def create_proposal(body: ProposalCreate, admin: User = Depends(require_admin),
                    db: Session = Depends(get_db)) -> dict:
    current = _current_state(db)
    proposal = MaintenanceProposal(
        created_by_id=admin.id, note=body.note, current_state=current,
        proposed_state={
            "tool_versions": body.proposed_tool_versions,
            "template_note": body.proposed_template_note,
        },
        state="PROPOSED",
    )
    db.add(proposal)
    db.flush()
    AuditService.append(
        db, actor=f"user:{admin.username}", action="MAINTENANCE_PROPOSED",
        object_type="maintenance_proposal", object_id=proposal.id,
        payload={"note": body.note, "proposed": proposal.proposed_state,
                 "current_versions": current["tool_versions"],
                 "current_template_set_hash": current["template_set_hash"]},
    )
    for a in db.execute(select(User).where(User.role == "ADMINISTRATOR")).scalars():
        db.add(Notification(user_id=a.id, kind="MAINTENANCE_PROPOSED",
                            title="Tool/template maintenance proposed",
                            body=f"{admin.username}: {body.note[:160]}"))
    db.commit()
    return _proposal_dto(db.get(MaintenanceProposal, proposal.id))


@router.post("/proposals/{proposal_id}/approve", dependencies=[Depends(require_csrf)])
def approve_proposal(proposal_id: str, body: Decision, admin: User = Depends(require_admin),
                     db: Session = Depends(get_db)) -> dict:
    return _decide(db, admin, proposal_id, "APPROVED", body.decision_note)


@router.post("/proposals/{proposal_id}/reject", dependencies=[Depends(require_csrf)])
def reject_proposal(proposal_id: str, body: Decision, admin: User = Depends(require_admin),
                    db: Session = Depends(get_db)) -> dict:
    return _decide(db, admin, proposal_id, "REJECTED", body.decision_note)


def _decide(db: Session, admin: User, proposal_id: str, new_state: str, note: str) -> dict:
    p = db.get(MaintenanceProposal, proposal_id)
    if p is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "proposal not found")
    if p.state != "PROPOSED":
        raise HTTPException(status.HTTP_409_CONFLICT, f"proposal already {p.state}")
    p.state = new_state
    p.decided_by_id = admin.id
    p.decided_at = dt.datetime.now(dt.timezone.utc)
    p.decision_note = note
    AuditService.append(
        db, actor=f"user:{admin.username}",
        action="MAINTENANCE_APPROVED" if new_state == "APPROVED" else "MAINTENANCE_REJECTED",
        object_type="maintenance_proposal", object_id=p.id,
        payload={"decision_note": note, "proposed": p.proposed_state},
    )
    db.commit()
    result = _proposal_dto(db.get(MaintenanceProposal, proposal_id))
    if new_state == "APPROVED":
        result["operator_action"] = (
            "Update the pinned versions in backend/Dockerfile (and the reviewed Nuclei "
            "templates + nuclei-manifest.json if changed), rebuild the worker image, and "
            "redeploy. Versions never change for a running execution."
        )
    return result
