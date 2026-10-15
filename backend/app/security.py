import hashlib
import hmac
import secrets
from datetime import timedelta
from fastapi import Depends, HTTPException, Request
from sqlalchemy import select
from .db import database
from .models import User, LoginSession, Agent, Host, now
from .config import settings


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def password_hash(password: str) -> str:
    salt = secrets.token_hex(16)
    key = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=16384, r=8, p=1)
    return f"scrypt${salt}${key.hex()}"


def password_matches(password: str, encoded: str) -> bool:
    try:
        _, salt, expected = encoded.split("$")
        actual = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=16384, r=8, p=1)
        return hmac.compare_digest(actual.hex(), expected)
    except (ValueError, TypeError):
        return False


async def resolve_session(db, token: str | None):
    if not token:
        return None
    return await db.scalar(select(User).join(LoginSession).where(
        LoginSession.token_hash == digest(token), LoginSession.expires_at > now(), User.is_active.is_(True)))


async def current_user(request: Request, db=Depends(database)):
    user = await resolve_session(db, request.cookies.get("hf_session"))
    if not user:
        raise HTTPException(401, "Требуется авторизация")
    if request.method not in {"GET", "HEAD", "OPTIONS"}:
        if request.headers.get("X-HoneyForge") != "1":
            raise HTTPException(403, "Отсутствует защитный заголовок CSRF")
        origin = request.headers.get("origin")
        if origin and origin != settings().allowed_origin:
            raise HTTPException(403, "Источник запроса не разрешён")
    return user


def roles(*allowed):
    async def dependency(user=Depends(current_user)):
        if user.role not in allowed:
            raise HTTPException(403, "Недостаточно прав")
        return user
    return dependency


async def identified_agent(request: Request, db=Depends(database)):
    agent_id = request.headers.get("X-Agent-ID", "")
    bearer = request.headers.get("Authorization", "")
    agent = await db.get(Agent, agent_id)
    if not bearer.startswith("Bearer ") or not agent:
        raise HTTPException(401, "Не удалось аутентифицировать агента")
    if not hmac.compare_digest(agent.token_hash, digest(bearer[7:])):
        raise HTTPException(401, "Не удалось аутентифицировать агента")
    return agent


async def current_agent(agent=Depends(identified_agent)):
    if not agent.approved or agent.retired or not agent.honeypot_id:
        raise HTTPException(401, "Требуется одобрение агента")
    return agent


async def current_controller(request: Request, db=Depends(database)):
    """Machine identity of a host deployment controller; never valid for operator endpoints."""
    host = await db.get(Host, request.headers.get("X-Controller-ID", ""))
    bearer = request.headers.get("Authorization", "")
    if not bearer.startswith("Bearer ") or not host or not host.controller_token_hash:
        raise HTTPException(401, "Не удалось аутентифицировать контроллер узла")
    if not hmac.compare_digest(host.controller_token_hash, digest(bearer[7:])):
        raise HTTPException(401, "Не удалось аутентифицировать контроллер узла")
    if not host.approved:
        raise HTTPException(403, "Узел лаборатории не одобрен")
    return host


async def current_notifier(request: Request):
    """Machine identity of the optional notifier; it can read pending notifications and nothing else."""
    expected = settings().notifier_token
    bearer = request.headers.get("Authorization", "")
    if not expected or not bearer.startswith("Bearer ") or not hmac.compare_digest(digest(expected), digest(bearer[7:])):
        raise HTTPException(401, "Не удалось аутентифицировать службу уведомлений")
    return "notifier"


async def issue_session(db, user, response):
    token = secrets.token_urlsafe(32)
    db.add(LoginSession(token_hash=digest(token), user_id=user.id,
                        expires_at=now() + timedelta(hours=settings().session_hours)))
    response.set_cookie("hf_session", token, httponly=True, secure=settings().cookie_secure,
                        samesite="strict", max_age=settings().session_hours * 3600, path="/")
