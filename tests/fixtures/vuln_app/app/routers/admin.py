from fastapi import APIRouter

router = APIRouter()


@router.get("/users")
def list_users():
    return [{"email": "a@example.com"}]


@router.delete("/users/{user_id}")
def delete_user(user_id: str):
    return {"deleted": user_id}
