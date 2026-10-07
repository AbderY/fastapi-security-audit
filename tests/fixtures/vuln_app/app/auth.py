from typing import Optional

import jwt
from fastapi import Depends, Header, HTTPException


def get_current_user(authorization: Optional[str] = Header(None)) -> dict:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Not authenticated")
    token = authorization.split(" ", 1)[1]
    return jwt.decode(token, "key", algorithms=["HS256"])


def require_admin(user: dict = Depends(get_current_user)) -> dict:
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admins only")
    return user


def get_optional_user(authorization: Optional[str] = Header(None)) -> Optional[dict]:
    if not authorization:
        return None
    try:
        return jwt.decode(authorization.split(" ", 1)[1], "key", algorithms=["HS256"])
    except Exception:
        return None


def verify_token(authorization: Optional[str]) -> dict:
    if not authorization:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return {"user_id": "u1"}
