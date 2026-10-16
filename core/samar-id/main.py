import os
import shutil
from typing import List
from fastapi import FastAPI, HTTPException, Depends, status, Request, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy import text

from database import init_db, engine, is_sqlite
from schemas import (
    UserRegister, UserLogin, UserResponse, TokenResponse,
    ProfileUpdate, PasswordChange, SessionItem
)
from security import hash_password, verify_password, create_access_token, decode_access_token

app = FastAPI(
    title="Samar ID — Universal Identity Provider",
    description="Samar OS ekotizimining to'liq va mustaqil shaxsiy autentifikatsiya xizmati.",
    version="1.3.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

security_scheme = HTTPBearer()

UPLOAD_DIR = os.path.join(os.path.dirname(__file__), "uploads", "avatars")
os.makedirs(UPLOAD_DIR, exist_ok=True)

@app.on_event("startup")
def on_startup():
    init_db()

def normalize_samar_id(raw_input: str) -> str:
    cleaned = raw_input.strip().lower()
    if cleaned.endswith("@samar.os"):
        return cleaned
    name_part = cleaned.replace("@", "").split(".")[0]
    return f"{name_part}@samar.os"

def parse_device_info(user_agent: str):
    if not user_agent:
        return "Noma'lum Qurilma", "device"
    ua = user_agent.lower()
    if "windows" in ua:
        return "Windows Kompyuter", "windows"
    elif "android" in ua:
        return "Android Smartfon", "android"
    elif "iphone" in ua or "ios" in ua:
        return "Apple iPhone", "apple"
    elif "macintosh" in ua or "mac os" in ua:
        return "Apple Mac", "apple"
    elif "linux" in ua:
        return "Linux Tizimi", "linux"
    return "Veb Brauzer", "browser"

def get_current_user_and_jti(credentials: HTTPAuthorizationCredentials = Depends(security_scheme)):
    token = credentials.credentials
    payload = decode_access_token(token)
    if not payload or "sub" not in payload or "jti" not in payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Muddati o'tgan yoki noto'g'ri sessiya",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    samar_id = payload["sub"]
    jti = payload["jti"]
    
    with engine.connect() as conn:
        sess = conn.execute(
            text("SELECT is_revoked FROM sessions WHERE token_jti = :jti"),
            {"jti": jti}
        ).mappings().first()
        
        if sess and sess["is_revoked"]:
            raise HTTPException(status_code=401, detail="Ushbu sessiya bekor qilingan.")
        
        user_row = conn.execute(
            text("""
                SELECT id, samar_id, full_name, email, phone, bio, specialty, avatar_path, role, two_factor_enabled, created_at
                FROM users WHERE samar_id = :samar_id
            """),
            {"samar_id": samar_id}
        ).mappings().first()
    
    if not user_row:
        raise HTTPException(status_code=404, detail="Foydalanuvchi topilmadi")
    
    user_dict = dict(user_row)
    user_dict["current_jti"] = jti
    user_dict["created_at"] = str(user_dict["created_at"])
    return user_dict

@app.get("/api/status")
def get_status():
    db_type = "SQLite (Local)" if is_sqlite else "PostgreSQL (Neon Cloud)"
    return {
        "service": "Samar ID",
        "status": "online",
        "version": "1.3.0",
        "database": db_type,
        "ecosystem": "Samar OS",
        "domain_format": "@samar.os",
        "message": "Samar ID to'liq barqaror holatda ishlamoqda."
    }

@app.post("/api/auth/register", response_model=TokenResponse)
def register(user_data: UserRegister, request: Request):
    samar_id_final = normalize_samar_id(user_data.samar_id)
    
    with engine.connect() as conn:
        existing = conn.execute(
            text("SELECT id FROM users WHERE samar_id = :samar_id OR (email IS NOT NULL AND email = :email)"),
            {"samar_id": samar_id_final, "email": user_data.email}
        ).mappings().first()
        
        if existing:
            raise HTTPException(status_code=400, detail=f"'{samar_id_final}' identifikatori allaqachon band.")
        
        pwd_hash = hash_password(user_data.password)
        
        if is_sqlite:
            res = conn.execute(
                text("INSERT INTO users (samar_id, full_name, email, password_hash) VALUES (:samar_id, :full_name, :email, :pwd_hash)"),
                {"samar_id": samar_id_final, "full_name": user_data.full_name, "email": user_data.email, "pwd_hash": pwd_hash}
            )
            user_id = res.lastrowid
        else:
            res = conn.execute(
                text("INSERT INTO users (samar_id, full_name, email, password_hash) VALUES (:samar_id, :full_name, :email, :pwd_hash) RETURNING id"),
                {"samar_id": samar_id_final, "full_name": user_data.full_name, "email": user_data.email, "pwd_hash": pwd_hash}
            )
            user_id = res.scalar()
            
        token, jti = create_access_token({"sub": samar_id_final, "user_id": user_id})
        device_name, _ = parse_device_info(request.headers.get("user-agent", ""))
        ip = request.client.host if request.client else "127.0.0.1"
        
        conn.execute(
            text("INSERT INTO sessions (user_id, token_jti, device_name, ip_address) VALUES (:uid, :jti, :dev, :ip)"),
            {"uid": user_id, "jti": jti, "dev": device_name, "ip": ip}
        )
        conn.commit()
        
        created_user = conn.execute(
            text("""
                SELECT id, samar_id, full_name, email, phone, bio, specialty, avatar_path, role, two_factor_enabled, created_at
                FROM users WHERE id = :uid
            """),
            {"uid": user_id}
        ).mappings().first()
        
        user_dict = dict(created_user)
        user_dict["created_at"] = str(user_dict["created_at"])
        
        return {
            "access_token": token,
            "token_type": "bearer",
            "user": user_dict
        }

@app.post("/api/auth/login", response_model=TokenResponse)
def login(login_data: UserLogin, request: Request):
    target_id = normalize_samar_id(login_data.samar_id_or_email)
    raw_input = login_data.samar_id_or_email.strip()

    with engine.connect() as conn:
        user_row = conn.execute(
            text("SELECT id, samar_id, full_name, email, phone, bio, specialty, avatar_path, role, two_factor_enabled, password_hash, created_at FROM users WHERE samar_id = :target OR email = :raw"),
            {"target": target_id, "raw": raw_input}
        ).mappings().first()
        
        if not user_row or not verify_password(login_data.password, user_row["password_hash"]):
            raise HTTPException(status_code=401, detail="Samar ID yoki parol noto'g'ri kiritildi.")
        
        user_dict = dict(user_row)
        del user_dict["password_hash"]
        user_dict["created_at"] = str(user_dict["created_at"])
        
        token, jti = create_access_token({"sub": user_dict["samar_id"], "user_id": user_dict["id"]})
        device_name, _ = parse_device_info(request.headers.get("user-agent", ""))
        ip = request.client.host if request.client else "127.0.0.1"
        
        conn.execute(
            text("INSERT INTO sessions (user_id, token_jti, device_name, ip_address) VALUES (:uid, :jti, :dev, :ip)"),
            {"uid": user_dict["id"], "jti": jti, "dev": device_name, "ip": ip}
        )
        conn.commit()
        
        return {
            "access_token": token,
            "token_type": "bearer",
            "user": user_dict
        }

@app.get("/api/auth/me", response_model=UserResponse)
def get_me(current: dict = Depends(get_current_user_and_jti)):
    return current

@app.put("/api/auth/profile", response_model=UserResponse)
def update_profile(data: ProfileUpdate, current: dict = Depends(get_current_user_and_jti)):
    with engine.connect() as conn:
        updates = []
        params = {"uid": current["id"]}
        if data.full_name is not None:
            updates.append("full_name = :full_name")
            params["full_name"] = data.full_name
        if data.phone is not None:
            updates.append("phone = :phone")
            params["phone"] = data.phone
        if data.bio is not None:
            updates.append("bio = :bio")
            params["bio"] = data.bio
        if data.specialty is not None:
            updates.append("specialty = :specialty")
            params["specialty"] = data.specialty
            
        if updates:
            conn.execute(text(f"UPDATE users SET {', '.join(updates)}, updated_at = CURRENT_TIMESTAMP WHERE id = :uid"), params)
            conn.commit()
            
        updated = conn.execute(
            text("""
                SELECT id, samar_id, full_name, email, phone, bio, specialty, avatar_path, role, two_factor_enabled, created_at
                FROM users WHERE id = :uid
            """),
            {"uid": current["id"]}
        ).mappings().first()
        
        res_dict = dict(updated)
        res_dict["created_at"] = str(res_dict["created_at"])
        return res_dict

@app.post("/api/auth/change-password")
def change_password(data: PasswordChange, current: dict = Depends(get_current_user_and_jti)):
    with engine.connect() as conn:
        user_row = conn.execute(text("SELECT password_hash FROM users WHERE id = :uid"), {"uid": current["id"]}).mappings().first()
        if not verify_password(data.old_password, user_row["password_hash"]):
            raise HTTPException(status_code=400, detail="Eski parol noto'g'ri kiritildi.")
            
        new_hash = hash_password(data.new_password)
        conn.execute(
            text("UPDATE users SET password_hash = :new_hash, updated_at = CURRENT_TIMESTAMP WHERE id = :uid"),
            {"new_hash": new_hash, "uid": current["id"]}
        )
        conn.execute(
            text("UPDATE sessions SET is_revoked = TRUE WHERE user_id = :uid AND token_jti != :curr_jti"),
            {"uid": current["id"], "curr_jti": current["current_jti"]}
        )
        conn.commit()
        return {"message": "Parol muvaffaqiyatli yangilandi. Boshqa barcha qurilmalar sessiyasi bekor qilindi."}

@app.post("/api/auth/upload-avatar")
async def upload_avatar(file: UploadFile = File(...), current: dict = Depends(get_current_user_and_jti)):
    extension = os.path.splitext(file.filename)[1].lower()
    if extension not in [".jpg", ".jpeg", ".png", ".webp"]:
        raise HTTPException(status_code=400, detail="Faqat JPG, PNG yoki WEBP rasmlar qabul qilinadi.")
        
    avatar_filename = f"avatar_{current['id']}{extension}"
    file_path = os.path.join(UPLOAD_DIR, avatar_filename)
    
    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)
        
    avatar_url = f"/uploads/avatars/{avatar_filename}"
    with engine.connect() as conn:
        conn.execute(
            text("UPDATE users SET avatar_path = :path WHERE id = :uid"),
            {"path": avatar_url, "uid": current["id"]}
        )
        conn.commit()
    
    return {"avatar_url": avatar_url, "message": "Profil rasmi yangilandi."}

@app.get("/api/auth/sessions", response_model=List[SessionItem])
def get_sessions(current: dict = Depends(get_current_user_and_jti)):
    try:
        with engine.connect() as conn:
            # PostgreSQL da boolean taqqoslash
            query = "SELECT id, token_jti, device_name, ip_address, last_active, is_revoked FROM sessions WHERE user_id = :uid AND (is_revoked IS FALSE OR is_revoked = 0) ORDER BY id DESC"
            rows = conn.execute(text(query), {"uid": current["id"]}).mappings().fetchall()
            
        result = []
        for r in rows:
            result.append({
                "id": r["id"],
                "device_name": r["device_name"],
                "ip_address": r["ip_address"],
                "last_active": str(r["last_active"])[:19] if r["last_active"] else "Hozir",
                "is_current": (r["token_jti"] == current["current_jti"])
            })
        return result
    except Exception as e:
        print("SESSIONS_FETCH_ERROR:", e)
        return []

@app.delete("/api/auth/sessions/{session_id}")
def revoke_session(session_id: int, current: dict = Depends(get_current_user_and_jti)):
    with engine.connect() as conn:
        rev_val = True if not is_sqlite else 1
        conn.execute(
            text(f"UPDATE sessions SET is_revoked = {rev_val} WHERE id = :sid AND user_id = :uid"),
            {"sid": session_id, "uid": current["id"]}
        )
        conn.commit()
    return {"message": "Qurilma sessiyasi bekor qilindi."}

@app.post("/api/auth/logout")
def logout(current: dict = Depends(get_current_user_and_jti)):
    with engine.connect() as conn:
        rev_val = True if not is_sqlite else 1
        conn.execute(
            text(f"UPDATE sessions SET is_revoked = {rev_val} WHERE token_jti = :jti"),
            {"jti": current["current_jti"]}
        )
        conn.commit()
    return {"message": "Tizimdan muvaffaqiyatli chiqildi."}

@app.get("/api/auth/export-data")
def export_data(current: dict = Depends(get_current_user_and_jti)):
    with engine.connect() as conn:
        user_row = conn.execute(
            text("SELECT id, samar_id, full_name, email, phone, bio, specialty, role, created_at FROM users WHERE id = :uid"),
            {"uid": current["id"]}
        ).mappings().first()
        sessions = conn.execute(
            text("SELECT device_name, ip_address, last_active FROM sessions WHERE user_id = :uid"),
            {"uid": current["id"]}
        ).mappings().fetchall()
    
    user_data = dict(user_row)
    user_data["created_at"] = str(user_data["created_at"])
    
    clean_sessions = []
    for s in sessions:
        sd = dict(s)
        sd["last_active"] = str(sd["last_active"])
        clean_sessions.append(sd)
    
    return {
        "ecosystem": "Samar OS",
        "export_date": "2026-10-16",
        "user_profile": user_data,
        "device_history": clean_sessions,
        "sovereign_guarantee": "Ushbu ma'lumotlar faqat sizning shaxsiy mulkingiz hisoblanadi."
    }

STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
UPLOADS_ROOT = os.path.join(os.path.dirname(__file__), "uploads")
if os.path.exists(STATIC_DIR):
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
if os.path.exists(UPLOADS_ROOT):
    app.mount("/uploads", StaticFiles(directory=UPLOADS_ROOT), name="uploads")

@app.get("/")
def serve_home():
    return FileResponse(os.path.join(STATIC_DIR, "index.html"))
