"""Deliberately vulnerable FastAPI app used by the test suite. Do not deploy."""

import os

import jwt
import requests
from fastapi import Depends, FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse

from app.auth import require_admin
from app.routers import admin, annotated, items, protected

SECRET_KEY = "s3cr3t-hardcoded-value-123"
JWT_SECRET = os.getenv("JWT_SECRET", "fallback-signing-key-42")

app = FastAPI(debug=True)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
)

app.include_router(admin.router, prefix="/admin")
app.include_router(items.router)
app.include_router(protected.router, dependencies=[Depends(require_admin)])
app.include_router(annotated.router)


@app.get("/login/callback")
def login_callback(next: str):
    return RedirectResponse(next)


@app.get("/debug/token")
def peek_token(token: str):
    return jwt.decode(token, options={"verify_signature": False})


@app.post("/sync")
def sync(request: Request, db=None):
    requests.get("https://partner.example.com/feed", verify=False)
    db.execute(f"DELETE FROM items WHERE owner = '{request.client.host}'")
    return {"ok": True}
