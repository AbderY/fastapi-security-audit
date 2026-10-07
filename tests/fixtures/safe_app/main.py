"""A small FastAPI app that follows the rules the scanners check."""

import os

import jwt
from fastapi import APIRouter, Depends, FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware

JWT_SECRET = os.environ["JWT_SECRET"]


def current_user(authorization: str = Header(...)) -> dict:
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Not authenticated")
    return jwt.decode(authorization[7:], JWT_SECRET, algorithms=["HS256"])


def admin_only(user: dict = Depends(current_user)) -> dict:
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admins only")
    return user


app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["https://app.example.com"], allow_credentials=True)

notes = APIRouter(prefix="/notes", dependencies=[Depends(current_user)])
admin = APIRouter(prefix="/admin", dependencies=[Depends(admin_only)])


@app.get("/health")
def health():
    return {"ok": True}


@app.post("/login")
def login(email: str):
    return {"sent": True}


@notes.get("/{note_id}")
def read_note(note_id: str):
    return {"id": note_id}


@notes.post("")
def create_note(text: str):
    return {"text": text}


@admin.delete("/users/{user_id}")
def delete_user(user_id: str):
    return {"deleted": user_id}


app.include_router(notes)
app.include_router(admin)
