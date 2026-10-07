from typing import Optional

from fastapi import APIRouter, Depends, Header, HTTPException

from ..auth import get_current_user, get_optional_user, verify_token

PREFIX = "/items"
router = APIRouter(prefix=PREFIX)


@router.get("/{item_id}")
def read_item(item_id: str):
    return {"id": item_id}


@router.get("/all")
def list_all_items():
    return []


@router.post("")
def create_item(user: dict = Depends(get_current_user)):
    return {"owner": user}


@router.post("/webhook")
def stripe_webhook(payload: dict):
    return {"received": True}


@router.put("/{item_id}")
def update_item(item_id: str, authorization: Optional[str] = Header(None)):
    verify_token(authorization)
    return {"id": item_id}


@router.patch("/{item_id}/share", dependencies=[Depends(get_optional_user)])
def share_item(item_id: str):
    return {"shared": item_id}


@router.post("/import")
def import_items(token: Optional[str] = None):
    return {"imported": 0}


@router.post("/legacy-sync")
def legacy_sync():
    """Switched off."""
    raise HTTPException(status_code=410, detail="Gone")
