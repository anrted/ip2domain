"""Authentication, user management, and base UI routes."""
import os
from fastapi import APIRouter, HTTPException, Request, Response
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field
from ip2domain.web.routers.common import auth_manager, _TEMPLATE_DIR

router = APIRouter(tags=["auth"])

class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=1024)

class UserCreateRequest(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    password: str = Field(min_length=12, max_length=1024)
    role: str = "user"

class UserActiveRequest(BaseModel):
    is_active: bool

class PasswordChangeRequest(BaseModel):
    password: str = Field(min_length=12, max_length=1024)

class OwnPasswordChangeRequest(BaseModel):
    current_password: str = Field(min_length=1, max_length=1024)
    new_password: str = Field(min_length=12, max_length=1024)

def _require_admin(request: Request) -> dict:
    user = getattr(request.state, "user", {})
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Administrator access required")
    return user

@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    user = getattr(request.state, "user", None)
    if user:
        return HTMLResponse('<script>window.location.href="/";</script>')
    template = _TEMPLATE_DIR / "login.html"
    return HTMLResponse(template.read_text(encoding="utf-8"))

@router.post("/api/auth/login")
async def login(req: LoginRequest, response: Response):
    user = auth_manager.authenticate(req.username, req.password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid username or password")
    token = auth_manager.create_session(user["id"])
    response.set_cookie(
        key="ip2domain_session",
        value=token,
        max_age=7 * 24 * 60 * 60,
        httponly=True,
        secure=os.environ.get("IP2DOMAIN_SECURE_COOKIES", "0") == "1",
        samesite="lax",
        path="/",
    )
    return {"user": user}

@router.post("/api/auth/logout")
async def logout(request: Request, response: Response):
    auth_manager.delete_session(request.cookies.get("ip2domain_session"))
    response.delete_cookie("ip2domain_session", path="/")
    return {"status": "logged_out"}

@router.get("/api/auth/me")
async def current_user(request: Request):
    return {"user": getattr(request.state, "user", None)}

@router.put("/api/auth/password")
async def change_own_password(req: OwnPasswordChangeRequest, request: Request, response: Response):
    user = getattr(request.state, "user", None)
    if not user or user.get("id") is None:
        raise HTTPException(status_code=400, detail="Password changes require a user session")
    authenticated = auth_manager.authenticate(user["username"], req.current_password)
    if not authenticated:
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    try:
        auth_manager.set_password(user["id"], req.new_password)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    token = auth_manager.create_session(user["id"])
    response.set_cookie(
        key="ip2domain_session",
        value=token,
        max_age=7 * 24 * 60 * 60,
        httponly=True,
        secure=os.environ.get("IP2DOMAIN_SECURE_COOKIES", "0") == "1",
        samesite="lax",
        path="/",
    )
    return {"status": "password_changed"}

@router.get("/api/users")
async def list_users(request: Request):
    _require_admin(request)
    return {"users": auth_manager.list_users()}

@router.post("/api/users", status_code=201)
async def create_user(req: UserCreateRequest, request: Request):
    _require_admin(request)
    try:
        return {"user": auth_manager.create_user(req.username, req.password, req.role)}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

@router.patch("/api/users/{user_id}/active")
async def set_user_active(user_id: int, req: UserActiveRequest, request: Request):
    actor = _require_admin(request)
    if actor.get("id") == user_id and not req.is_active:
        raise HTTPException(status_code=400, detail="You cannot disable your own account")
    user = auth_manager.set_active(user_id, req.is_active)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return {"user": user}

@router.put("/api/users/{user_id}/password")
async def set_user_password(user_id: int, req: PasswordChangeRequest, request: Request):
    actor = _require_admin(request)
    if actor.get("id") != user_id and actor.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Not allowed")
    try:
        user = auth_manager.set_password(user_id, req.password)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return {"user": user}
