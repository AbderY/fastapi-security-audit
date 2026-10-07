from typing import Annotated

from fastapi import APIRouter, Depends

from app.auth import get_current_user

CurrentUser = Annotated[dict, Depends(get_current_user)]

router = APIRouter(prefix="/v2")


@router.get("/me")
def me(user: CurrentUser):
    return user


@router.get("/admin/stats")
def admin_stats(user: CurrentUser):
    return {"users": 3}
