from fastapi import APIRouter

router = APIRouter(prefix="/internal")


@router.post("/rebuild")
def rebuild_index():
    return {"started": True}
