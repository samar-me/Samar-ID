import os
import shutil
import sqlite3
from typing import List
from fastapi import FastAPI, HTTPException, Depends, status, Request, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from database import init_db, get_db
from schemas import (
    UserRegister, UserLogin, UserResponse, TokenResponse,
    ProfileUpdate, PasswordChange, SessionItem
)
from security import hash_password, verify_password, create_access_token, decode_access_token

app = FastAPI(
    title="Samar ID — Universal Identity Provider",
    description="Samar OS ekotizimining to'liq va mustaqil shaxsiy autentifikatsiya xizmati.",
    version="1.1.0"
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
    # Agar faqat nom yozilgan bo'lsa (masalan: shoxrux)
    name_part = cleaned.replace("@", "").split(".")[0]
    return f"{name_part}@samar.os"

def parse_device_name(user_agent: str) -> str:
    if not user_agent:
        return "Noma'lum Qurilma"
    ua = user_agent.lower()
    if "windows" in ua:
        return "Windows Kompyuter"
    elif "android" in ua:
        return "Android Smartfon"
    elif "iphone" in ua or "ios" in ua:
        return "Apple iPhone"
    elif "macintosh" in ua or "mac os" in ua:
        return "Apple Mac"
    elif "linux" in ua:
        return "Linux Qurilma"
    return "Veb Qurilma"

def get_current_user_and_jti(credentials: HTTPAuthorizationCredentials = Depends(security_scheme)):
    token = credentials.credentials
    payload = decode_access_token(token)
    if not payload or "sub" not in payload or "jti" not in payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Noto'g'ri yoki muddati o'tgan Samar ID tokeni",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    samar_id = payload["sub"]
    jti = payload["jti"]
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT is_revoked FROM sessions WHERE token_jti = ?", (jti,))
    sess = cursor.fetchone()
    if sess and sess["is_revoked"]:
        conn.close()
        raise HTTPException(status_code=401, detail="Ushbu sessiya bekor qilingan. Qaytadan kiring.")
    
    cursor.execute("""
        SELECT id, samar_id, full_name, email, phone, bio, specialty, avatar_path, role, two_factor_enabled, created_at
        FROM users WHERE samar_id = ?
    """, (samar_id,))
    row = cursor.fetchone()
    conn.close()
    
    if not row:
        raise HTTPException(status_code=404, detail="Foydalanuvchi topilmadi")
    
    user_dict = dict(row)
    user_dict["current_jti"] = jti
    return user_dict

@app.get("/api/status")
def get_status():
    return {
        "service": "Samar ID",
        "status": "online",
        "version": "1.1.0",
        "ecosystem": "Samar OS",
        "domain_format": "@samar.os",
        "message": "Samar ID xizmati to'liq quvvat bilan ishlamoqda. The future is now."
    }

@app.post("/api/auth/register", response_model=TokenResponse)
def register(user_data: UserRegister, request: Request):
    conn = get_db()
    cursor = conn.cursor()
    
    samar_id_final = normalize_samar_id(user_data.samar_id)
    
    cursor.execute("SELECT id FROM users WHERE samar_id = ? OR (email IS NOT NULL AND email = ?)", (samar_id_final, user_data.email))
    if cursor.fetchone():
        conn.close()
        raise HTTPException(status_code=400, detail=f"'{samar_id_final}' identifikatori allaqachon band. Boshqa nom tanlang.")
    
    pwd_hash = hash_password(user_data.password)
    
    cursor.execute(
        "INSERT INTO users (samar_id, full_name, email, password_hash) VALUES (?, ?, ?, ?)",
        (samar_id_final, user_data.full_name, user_data.email, pwd_hash)
    )
    user_id = cursor.lastrowid
    
    token, jti = create_access_token({"sub": samar_id_final, "user_id": user_id})
    device = parse_device_name(request.headers.get("user-agent", ""))
    ip = request.client.host if request.client else "127.0.0.1"
    
    cursor.execute(
        "INSERT INTO sessions (user_id, token_jti, device_name, ip_address) VALUES (?, ?, ?, ?)",
        (user_id, jti, device, ip)
    )
    conn.commit()
    
    cursor.execute("""
        SELECT id, samar_id, full_name, email, phone, bio, specialty, avatar_path, role, two_factor_enabled, created_at
        FROM users WHERE id = ?
    """, (user_id,))
    created_user = dict(cursor.fetchone())
    conn.close()
    
    return {
        "access_token": token,
        "token_type": "bearer",
        "user": created_user
    }

@app.post("/api/auth/login", response_model=TokenResponse)
def login(login_data: UserLogin, request: Request):
    target_id = normalize_samar_id(login_data.samar_id_or_email)
    raw_input = login_data.samar_id_or_email.strip()

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, samar_id, full_name, email, phone, bio, specialty, avatar_path, role, two_factor_enabled, password_hash, created_at FROM users WHERE samar_id = ? OR email = ?",
        (target_id, raw_input)
    )
    row = cursor.fetchone()
    
    if not row or not verify_password(login_data.password, row["password_hash"]):
        conn.close()
        raise HTTPException(status_code=401, detail="Samar ID yoki parol noto'g'ri kiritildi.")
    
    user_dict = dict(row)
    del user_dict["password_hash"]
    
    token, jti = create_access_token({"sub": user_dict["samar_id"], "user_id": user_dict["id"]})
    device = parse_device_name(request.headers.get("user-agent", ""))
    ip = request.client.host if request.client else "127.0.0.1"
    
    cursor.execute(
        "INSERT INTO sessions (user_id, token_jti, device_name, ip_address) VALUES (?, ?, ?, ?)",
        (user_dict["id"], jti, device, ip)
    )
    conn.commit()
    conn.close()
    
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
    conn = get_db()
    cursor = conn.cursor()
    
    updates = []
    params = []
    if data.full_name is not None:
        updates.append("full_name = ?")
        params.append(data.full_name)
    if data.phone is not None:
        updates.append("phone = ?")
        params.append(data.phone)
    if data.bio is not None:
        updates.append("bio = ?")
        params.append(data.bio)
    if data.specialty is not None:
        updates.append("specialty = ?")
        params.append(data.specialty)
        
    if updates:
        params.append(current["id"])
        cursor.execute(f"UPDATE users SET {', '.join(updates)}, updated_at = CURRENT_TIMESTAMP WHERE id = ?", params)
        conn.commit()
        
    cursor.execute("""
        SELECT id, samar_id, full_name, email, phone, bio, specialty, avatar_path, role, two_factor_enabled, created_at
        FROM users WHERE id = ?
    """, (current["id"],))
    updated_user = dict(cursor.fetchone())
    conn.close()
    return updated_user

@app.post("/api/auth/change-password")
def change_password(data: PasswordChange, current: dict = Depends(get_current_user_and_jti)):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT password_hash FROM users WHERE id = ?", (current["id"],))
    user = cursor.fetchone()
    
    if not verify_password(data.old_password, user["password_hash"]):
        conn.close()
        raise HTTPException(status_code=400, detail="Eski parol noto'g'ri kiritildi.")
        
    new_hash = hash_password(data.new_password)
    cursor.execute("UPDATE users SET password_hash = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?", (new_hash, current["id"]))
    cursor.execute("UPDATE sessions SET is_revoked = 1 WHERE user_id = ? AND token_jti != ?", (current["id"], current["current_jti"]))
    conn.commit()
    conn.close()
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
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET avatar_path = ? WHERE id = ?", (avatar_url, current["id"]))
    conn.commit()
    conn.close()
    
    return {"avatar_url": avatar_url, "message": "Profil rasmi yangilandi."}

@app.get("/api/auth/sessions", response_model=List[SessionItem])
def get_sessions(current: dict = Depends(get_current_user_and_jti)):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, token_jti, device_name, ip_address, last_active, is_revoked
        FROM sessions WHERE user_id = ? AND is_revoked = 0 ORDER BY id DESC
    """, (current["id"],))
    rows = cursor.fetchall()
    conn.close()
    
    result = []
    for r in rows:
        result.append({
            "id": r["id"],
            "device_name": r["device_name"],
            "ip_address": r["ip_address"],
            "last_active": r["last_active"],
            "is_current": (r["token_jti"] == current["current_jti"])
        })
    return result

@app.delete("/api/auth/sessions/{session_id}")
def revoke_session(session_id: int, current: dict = Depends(get_current_user_and_jti)):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("UPDATE sessions SET is_revoked = 1 WHERE id = ? AND user_id = ?", (session_id, current["id"]))
    conn.commit()
    conn.close()
    return {"message": "Qurilma sessiyasi bekor qilindi."}

@app.post("/api/auth/logout")
def logout(current: dict = Depends(get_current_user_and_jti)):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("UPDATE sessions SET is_revoked = 1 WHERE token_jti = ?", (current["current_jti"],))
    conn.commit()
    conn.close()
    return {"message": "Tizimdan muvaffaqiyatli chiqildi."}

@app.get("/api/auth/export-data")
def export_data(current: dict = Depends(get_current_user_and_jti)):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id, samar_id, full_name, email, phone, bio, specialty, role, created_at FROM users WHERE id = ?", (current["id"],))
    user_data = dict(cursor.fetchone())
    cursor.execute("SELECT device_name, ip_address, last_active FROM sessions WHERE user_id = ?", (current["id"],))
    sessions = [dict(s) for s in cursor.fetchall()]
    conn.close()
    
    return {
        "ecosystem": "Samar OS",
        "export_date": "2026-10-16",
        "user_profile": user_data,
        "device_history": sessions,
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
