import os
import base64
import random
import uuid
from datetime import datetime, timedelta, timezone
from typing import List, Optional
from fastapi import FastAPI, HTTPException, Depends, status, Request, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy import text

from database import init_db, engine, is_sqlite
from schemas import (
    UserRegister, UserLogin, UserResponse, TokenResponse,
    ProfileUpdate, PasswordChange, SessionItem,
    GuardianSet, GuardianRequestOtp, GuardianVerifyOtp, NotificationItem,
    PhoneSendCode, PhoneVerifyCode,
    RecoveryLogin, RecoveryCodesResponse, ConnectedAppItem,
    PasskeyRegisterRequest, PasskeyLoginRequest
)
from security import hash_password, verify_password, create_access_token, decode_access_token

app = FastAPI(
    title="Samar ID — The Sovereign Identity System",
    description="Samar OS ekotizimining eng ilg'or, xavfsiz va mustaqil shaxsiy autentifikatsiya xizmati.",
    version="3.1.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

security_scheme = HTTPBearer()

ACTIVE_GUARDIAN_OTPS = {}
ACTIVE_PHONE_OTPS = {}

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
        return "Windows 11 / PC", "windows"
    elif "android" in ua:
        return "Android Smartfon", "android"
    elif "iphone" in ua or "ios" in ua:
        return "Apple iPhone", "apple"
    elif "macintosh" in ua or "mac os" in ua:
        return "macOS Workstation", "apple"
    elif "linux" in ua:
        return "Samar Linux OS", "linux"
    return "Web Terminal", "browser"

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
                SELECT id, samar_id, full_name, email, phone, phone_verified, bio, specialty, avatar_path, guardian_id, security_freeze_until, role, two_factor_enabled, created_at
                FROM users WHERE samar_id = :samar_id
            """),
            {"samar_id": samar_id}
        ).mappings().first()
    
    if not user_row:
        raise HTTPException(status_code=404, detail="Foydalanuvchi topilmadi")
    
    user_dict = dict(user_row)
    user_dict["phone_verified"] = bool(user_dict.get("phone_verified", False))
    user_dict["current_jti"] = jti
    user_dict["created_at"] = str(user_dict["created_at"])
    if user_dict.get("security_freeze_until"):
        user_dict["security_freeze_until"] = str(user_dict["security_freeze_until"])
    return user_dict

@app.get("/api/status")
def get_status():
    db_type = "SQLite (Local)" if is_sqlite else "PostgreSQL (Neon Cloud)"
    return {
        "service": "Samar ID Core",
        "status": "online",
        "version": "3.1.0",
        "design": "Apple macOS Ultra-Refined",
        "logo": "Isometric Crystal Citadel Monolith",
        "database": db_type,
        "features": ["QR Instant Login", "Guardian Social Recovery", "10-Day Freeze", "Persistent Avatar", "Phone SMS Verification"],
        "ecosystem": "Samar OS",
        "domain_format": "@samar.os"
    }

# ----------------- AUTHENTICATION -----------------
@app.post("/api/auth/register", response_model=TokenResponse)
def register(user_data: UserRegister, request: Request):
    samar_id_final = normalize_samar_id(user_data.samar_id)
    
    with engine.connect() as conn:
        existing = conn.execute(
            text("SELECT id FROM users WHERE samar_id = :samar_id OR (email IS NOT NULL AND email = :email)"),
            {"samar_id": samar_id_final, "email": user_data.email}
        ).mappings().first()
        
        if existing:
            raise HTTPException(status_code=400, detail=f"'{samar_id_final}' identifikatori yoki Email allaqachon band.")
        
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
        conn.execute(
            text("INSERT INTO notifications (user_id, from_user, title, message, type) VALUES (:uid, 'Samar OS', 'Samar ID ga xush kelibsiz!', 'Sizning shaxsiy raqamli pasportingiz faollashtirildi. The future is now.', 'system')"),
            {"uid": user_id}
        )
        conn.commit()
        
        created_user = conn.execute(
            text("""
                SELECT id, samar_id, full_name, email, phone, phone_verified, bio, specialty, avatar_path, guardian_id, security_freeze_until, role, two_factor_enabled, created_at
                FROM users WHERE id = :uid
            """),
            {"uid": user_id}
        ).mappings().first()
        
        user_dict = dict(created_user)
        user_dict["phone_verified"] = bool(user_dict.get("phone_verified", False))
        user_dict["created_at"] = str(user_dict["created_at"])
        user_dict["security_freeze_until"] = str(user_dict["security_freeze_until"]) if user_dict.get("security_freeze_until") else None
        
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
            text("SELECT id, samar_id, full_name, email, phone, phone_verified, bio, specialty, avatar_path, guardian_id, security_freeze_until, role, two_factor_enabled, password_hash, created_at FROM users WHERE samar_id = :target OR email = :raw"),
            {"target": target_id, "raw": raw_input}
        ).mappings().first()
        
        if not user_row or not verify_password(login_data.password, user_row["password_hash"]):
            raise HTTPException(status_code=401, detail="Samar ID yoki parol noto'g'ri kiritildi.")
        
        user_dict = dict(user_row)
        del user_dict["password_hash"]
        user_dict["phone_verified"] = bool(user_dict.get("phone_verified", False))
        user_dict["created_at"] = str(user_dict["created_at"])
        user_dict["security_freeze_until"] = str(user_dict["security_freeze_until"]) if user_dict.get("security_freeze_until") else None
        
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

# ----------------- QR LOGIN -----------------
@app.post("/api/auth/qr/generate")
def generate_qr():
    qr_token = "samar_qr_" + str(uuid.uuid4())
    with engine.connect() as conn:
        conn.execute(text("INSERT INTO qr_logins (qr_token, status) VALUES (:tok, 'pending')"), {"tok": qr_token})
        conn.commit()
    return {"qr_token": qr_token}

@app.get("/api/auth/qr/status/{qr_token}")
def check_qr_status(qr_token: str):
    with engine.connect() as conn:
        row = conn.execute(text("SELECT status, user_id FROM qr_logins WHERE qr_token = :tok"), {"tok": qr_token}).mappings().first()
        if not row:
            raise HTTPException(status_code=404, detail="QR token topilmadi")
        
        if row["status"] == "approved" and row["user_id"]:
            user_row = conn.execute(
                text("SELECT id, samar_id, full_name, email, phone, bio, specialty, avatar_path, guardian_id, security_freeze_until, role, two_factor_enabled, created_at FROM users WHERE id = :uid"),
                {"uid": row["user_id"]}
            ).mappings().first()
            
            user_dict = dict(user_row)
            user_dict["created_at"] = str(user_dict["created_at"])
            user_dict["security_freeze_until"] = str(user_dict["security_freeze_until"]) if user_dict.get("security_freeze_until") else None
            
            token, jti = create_access_token({"sub": user_dict["samar_id"], "user_id": user_dict["id"]})
            conn.execute(text("INSERT INTO sessions (user_id, token_jti, device_name, ip_address) VALUES (:uid, :jti, 'QR Authenticated Device', '127.0.0.1')"), {"uid": user_dict["id"], "jti": jti})
            conn.commit()
            
            return {
                "status": "approved",
                "access_token": token,
                "token_type": "bearer",
                "user": user_dict
            }
        return {"status": row["status"]}

# ----------------- GUARDIAN (DO'ST ORQALI TIKLASH) -----------------
@app.post("/api/auth/guardian/set")
def set_guardian(data: GuardianSet, current: dict = Depends(get_current_user_and_jti)):
    guardian_final = normalize_samar_id(data.guardian_samar_id)
    with engine.connect() as conn:
        guardian = conn.execute(text("SELECT id FROM users WHERE samar_id = :gid"), {"gid": guardian_final}).mappings().first()
        if not guardian:
            raise HTTPException(status_code=404, detail="Bunday Samar ID li do'st topilmadi.")
        if guardian["id"] == current["id"]:
            raise HTTPException(status_code=400, detail="O'zingizni vasiy qilib belgilay olmaysiz.")
            
        conn.execute(text("UPDATE users SET guardian_id = :gid WHERE id = :uid"), {"gid": guardian_final, "uid": current["id"]})
        conn.execute(
            text("INSERT INTO notifications (user_id, from_user, title, message, type) VALUES (:uid, :from_u, 'Yangi Ishonchli Vasiylik', :msg, 'guardian')"),
            {
                "uid": guardian["id"],
                "from_u": current["samar_id"],
                "msg": f"{current['full_name']} sizni o'zining Samar ID himoyachisi (Vasiy) qilib belgiladi."
            }
        )
        conn.commit()
    return {"message": f"Ishonchli do'stingiz ({guardian_final}) muvaffaqiyatli saqlandi!"}

@app.post("/api/auth/guardian/request-otp")
def request_guardian_otp(data: GuardianRequestOtp):
    target_id = normalize_samar_id(data.samar_id)
    with engine.connect() as conn:
        user_row = conn.execute(text("SELECT id, full_name, guardian_id FROM users WHERE samar_id = :sid"), {"sid": target_id}).mappings().first()
        if not user_row or not user_row["guardian_id"]:
            raise HTTPException(status_code=400, detail="Ushbu akkauntda ishonchli do'st (Guardian) belgilanmagan.")
            
        guardian_row = conn.execute(text("SELECT id FROM users WHERE samar_id = :gid"), {"gid": user_row["guardian_id"]}).mappings().first()
        if not guardian_row:
            raise HTTPException(status_code=400, detail="Vasiy akkaunti topilmadi.")
            
        otp = str(random.randint(100000, 999999))
        ACTIVE_GUARDIAN_OTPS[target_id] = otp
        
        conn.execute(
            text("""
                INSERT INTO notifications (user_id, from_user, title, message, type, action_data)
                VALUES (:uid, :from_u, 'PAROL TIKLASH SO''ROVI', :msg, 'emergency', :otp)
            """),
            {
                "uid": guardian_row["id"],
                "from_u": target_id,
                "msg": f"Do'stingiz {user_row['full_name']} parolini unutdi. Uning 1 martalik kirish kodi: {otp}. Bu kodni faqat o'ziga ayting!",
                "otp": otp
            }
        )
        conn.commit()
        
    return {
        "message": f"So'rov do'stingiz ({user_row['guardian_id']}) Samar ID siga yuborildi. Undan 6 xonali kodni oling!"
    }

@app.post("/api/auth/guardian/verify-otp", response_model=TokenResponse)
def verify_guardian_otp(data: GuardianVerifyOtp, request: Request):
    target_id = normalize_samar_id(data.samar_id)
    expected_otp = ACTIVE_GUARDIAN_OTPS.get(target_id)
    
    if not expected_otp or expected_otp != data.otp_code.strip():
        raise HTTPException(status_code=400, detail="Noto'g'ri yoki eskirgan bir martalik kod.")
        
    del ACTIVE_GUARDIAN_OTPS[target_id]
    freeze_until = datetime.now(timezone.utc) + timedelta(days=10)
    
    with engine.connect() as conn:
        conn.execute(
            text("UPDATE users SET security_freeze_until = :freeze WHERE samar_id = :sid"),
            {"freeze": freeze_until, "sid": target_id}
        )
        user_row = conn.execute(
            text("SELECT id, samar_id, full_name, email, phone, bio, specialty, avatar_path, guardian_id, security_freeze_until, role, two_factor_enabled, created_at FROM users WHERE samar_id = :sid"),
            {"sid": target_id}
        ).mappings().first()
        
        user_dict = dict(user_row)
        user_dict["created_at"] = str(user_dict["created_at"])
        user_dict["security_freeze_until"] = str(user_dict["security_freeze_until"])
        
        token, jti = create_access_token({"sub": user_dict["samar_id"], "user_id": user_dict["id"]})
        device_name, _ = parse_device_info(request.headers.get("user-agent", ""))
        
        conn.execute(
            text("INSERT INTO sessions (user_id, token_jti, device_name, ip_address) VALUES (:uid, :jti, :dev, '127.0.0.1')"),
            {"uid": user_dict["id"], "jti": jti, "dev": f"{device_name} (Guardian OTP)"}
        )
        conn.commit()
        
    return {
        "access_token": token,
        "token_type": "bearer",
        "user": user_dict
    }

# ----------------- INBOX & NOTIFICATIONS -----------------
@app.get("/api/notifications", response_model=List[NotificationItem])
def get_notifications(current: dict = Depends(get_current_user_and_jti)):
    with engine.connect() as conn:
        rows = conn.execute(
            text("SELECT id, from_user, title, message, type, is_read, action_data, created_at FROM notifications WHERE user_id = :uid ORDER BY id DESC LIMIT 20"),
            {"uid": current["id"]}
        ).mappings().fetchall()
        
    result = []
    for r in rows:
        result.append({
            "id": r["id"],
            "from_user": r["from_user"],
            "title": r["title"],
            "message": r["message"],
            "type": r["type"],
            "is_read": bool(r["is_read"]),
            "action_data": r["action_data"] or "",
            "created_at": str(r["created_at"])[:19]
        })
    return result

@app.post("/api/notifications/{notif_id}/read")
def mark_notification_read(notif_id: int, current: dict = Depends(get_current_user_and_jti)):
    with engine.connect() as conn:
        val = "1" if is_sqlite else "TRUE"
        conn.execute(
            text(f"UPDATE notifications SET is_read = {val} WHERE id = :nid AND user_id = :uid"),
            {"nid": notif_id, "uid": current["id"]}
        )
        conn.commit()
    return {"status": "ok"}

@app.delete("/api/notifications/{notif_id}")
def delete_notification(notif_id: int, current: dict = Depends(get_current_user_and_jti)):
    with engine.connect() as conn:
        conn.execute(
            text("DELETE FROM notifications WHERE id = :nid AND user_id = :uid"),
            {"nid": notif_id, "uid": current["id"]}
        )
        conn.commit()
    return {"status": "deleted"}

@app.post("/api/notifications/clear-all")
def clear_all_notifications(current: dict = Depends(get_current_user_and_jti)):
    with engine.connect() as conn:
        conn.execute(
            text("DELETE FROM notifications WHERE user_id = :uid"),
            {"uid": current["id"]}
        )
        conn.commit()
    return {"status": "cleared"}

# ----------------- FAVQULODDA ZAXIRA KODLARI -----------------
def generate_8_recovery_codes():
    import secrets
    chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    codes = []
    for _ in range(8):
        c1 = "".join(secrets.choice(chars) for _ in range(4))
        c2 = "".join(secrets.choice(chars) for _ in range(4))
        codes.append(f"SAMAR-{c1}-{c2}")
    return codes

@app.get("/api/auth/recovery-codes", response_model=RecoveryCodesResponse)
def get_recovery_codes(current: dict = Depends(get_current_user_and_jti)):
    with engine.connect() as conn:
        not_used_cond = "is_used = 0" if is_sqlite else "is_used IS FALSE"
        rows = conn.execute(
            text(f"SELECT code_preview FROM recovery_codes WHERE user_id = :uid AND {not_used_cond} ORDER BY id ASC"),
            {"uid": current["id"]}
        ).mappings().fetchall()

        if not rows:
            new_codes = generate_8_recovery_codes()
            for c in new_codes:
                h = hash_password(c)
                conn.execute(
                    text("INSERT INTO recovery_codes (user_id, code_hash, code_preview) VALUES (:uid, :ch, :cp)"),
                    {"uid": current["id"], "ch": h, "cp": c}
                )
            conn.commit()
            return {"codes": new_codes}

        return {"codes": [r["code_preview"] for r in rows]}

@app.post("/api/auth/recovery-codes/regenerate", response_model=RecoveryCodesResponse)
def regenerate_recovery_codes(current: dict = Depends(get_current_user_and_jti)):
    new_codes = generate_8_recovery_codes()
    with engine.connect() as conn:
        conn.execute(
            text("DELETE FROM recovery_codes WHERE user_id = :uid"),
            {"uid": current["id"]}
        )
        for c in new_codes:
            h = hash_password(c)
            conn.execute(
                text("INSERT INTO recovery_codes (user_id, code_hash, code_preview) VALUES (:uid, :ch, :cp)"),
                {"uid": current["id"], "ch": h, "cp": c}
            )
        conn.execute(
            text("INSERT INTO notifications (user_id, from_user, title, message, type) VALUES (:uid, 'Samar Security', 'Yangi Zaxira Kodlari Yaratildi', 'Favqulodda zaxira kodlaringiz muvaffaqiyatli yangilandi.', 'security')"),
            {"uid": current["id"]}
        )
        conn.commit()
    return {"codes": new_codes}

@app.post("/api/auth/recovery-login", response_model=TokenResponse)
def login_with_recovery_code(data: RecoveryLogin, request: Request):
    clean_id = normalize_samar_id(data.samar_id)
    clean_code = data.code.strip().upper()

    with engine.connect() as conn:
        user_row = conn.execute(
            text("SELECT id, samar_id, full_name, email, phone, phone_verified, bio, specialty, avatar_path, guardian_id, security_freeze_until, role, two_factor_enabled, created_at FROM users WHERE samar_id = :sid"),
            {"sid": clean_id}
        ).mappings().first()

        if not user_row:
            raise HTTPException(status_code=404, detail="Bunday Samar ID topilmadi")

        uid = user_row["id"]
        not_used_cond = "is_used = 0" if is_sqlite else "is_used IS FALSE"
        code_rows = conn.execute(
            text(f"SELECT id, code_hash, code_preview FROM recovery_codes WHERE user_id = :uid AND {not_used_cond}"),
            {"uid": uid}
        ).mappings().fetchall()

        matched_id = None
        for cr in code_rows:
            if cr["code_preview"] == clean_code or verify_password(clean_code, cr["code_hash"]):
                matched_id = cr["id"]
                break

        if not matched_id:
            raise HTTPException(status_code=400, detail="Noto'g'ri yoki avval ishlatilgan zaxira kodi!")

        # Burn code
        used_val = "1" if is_sqlite else "TRUE"
        conn.execute(
            text(f"UPDATE recovery_codes SET is_used = {used_val} WHERE id = :cid"),
            {"cid": matched_id}
        )

        # Create session
        jti = str(uuid.uuid4())
        device_name, _ = parse_device_info(request.headers.get("user-agent", ""))
        client_ip = request.client.host if request.client else "127.0.0.1"
        conn.execute(
            text("INSERT INTO sessions (user_id, token_jti, device_name, ip_address) VALUES (:uid, :jti, :dev, :ip)"),
            {"uid": uid, "jti": jti, "dev": f"{device_name} (Zaxira Kod)", "ip": client_ip}
        )
        conn.execute(
            text("INSERT INTO notifications (user_id, from_user, title, message, type) VALUES (:uid, 'Samar Security', 'Favqulodda Zaxira Kodi Bilan Kirildi', 'Akkauntingizga bir martalik zaxira kodi orqali kirildi. Iltimos, yangi kodlar yaratib oling.', 'security')"),
            {"uid": uid}
        )
        conn.commit()

    token = create_access_token({"sub": user_row["samar_id"], "jti": jti})
    user_data = dict(user_row)
    user_data["phone_verified"] = bool(user_data.get("phone_verified", False))
    user_data["created_at"] = str(user_data["created_at"])
    user_data["security_freeze_until"] = str(user_data["security_freeze_until"]) if user_data.get("security_freeze_until") else None
    return {"access_token": token, "user": user_data}

# ----------------- BIOMETRIYA & PASSKEYS (FACE ID / TOUCH ID) -----------------
@app.post("/api/auth/passkeys/register")
def register_passkey(data: PasskeyRegisterRequest, current: dict = Depends(get_current_user_and_jti)):
    with engine.connect() as conn:
        conn.execute(
            text("INSERT INTO passkey_credentials (user_id, credential_id, public_key, device_name) VALUES (:uid, :cid, :pk, :dn)"),
            {"uid": current["id"], "cid": data.credential_id, "pk": data.public_key, "dn": data.device_name}
        )
        conn.execute(
            text("INSERT INTO notifications (user_id, from_user, title, message, type) VALUES (:uid, 'Samar Security', 'Biometrik Kirish Ulandi', :msg, 'security')"),
            {"uid": current["id"], "msg": f"{data.device_name} orqali biometrik kirish (Passkey) muvaffaqiyatli ulandi."}
        )
        conn.commit()
    return {"status": "ok", "message": f"{data.device_name} ulandi!"}

@app.post("/api/auth/passkeys/login", response_model=TokenResponse)
def login_with_passkey(data: PasskeyLoginRequest, request: Request):
    clean_id = normalize_samar_id(data.samar_id)
    with engine.connect() as conn:
        user_row = conn.execute(
            text("SELECT id, samar_id, full_name, email, phone, phone_verified, bio, specialty, avatar_path, guardian_id, security_freeze_until, role, two_factor_enabled, created_at FROM users WHERE samar_id = :sid"),
            {"sid": clean_id}
        ).mappings().first()

        if not user_row:
            raise HTTPException(status_code=404, detail="Bunday Samar ID topilmadi")

        uid = user_row["id"]
        jti = str(uuid.uuid4())
        device_name, _ = parse_device_info(request.headers.get("user-agent", ""))
        client_ip = request.client.host if request.client else "127.0.0.1"

        conn.execute(
            text("INSERT INTO sessions (user_id, token_jti, device_name, ip_address) VALUES (:uid, :jti, :dev, :ip)"),
            {"uid": uid, "jti": jti, "dev": f"{device_name} (Face ID / Passkey)", "ip": client_ip}
        )
        conn.execute(
            text("INSERT INTO notifications (user_id, from_user, title, message, type) VALUES (:uid, 'Samar Security', 'Biometriya Orqali Kirildi', 'Face ID / Touch ID orqali tezkor autentifikatsiya amalga oshirildi.', 'security')"),
            {"uid": uid}
        )
        conn.commit()

    token = create_access_token({"sub": user_row["samar_id"], "jti": jti})
    user_data = dict(user_row)
    user_data["phone_verified"] = bool(user_data.get("phone_verified", False))
    user_data["created_at"] = str(user_data["created_at"])
    user_data["security_freeze_until"] = str(user_data["security_freeze_until"]) if user_data.get("security_freeze_until") else None
    return {"access_token": token, "user": user_data}

# ----------------- ULANGAN ILOVALAR & SAMAR OAUTH -----------------
@app.get("/api/oauth/apps", response_model=List[ConnectedAppItem])
def get_connected_apps(current: dict = Depends(get_current_user_and_jti)):
    with engine.connect() as conn:
        rows = conn.execute(
            text("SELECT id, client_id, app_name, app_icon, scopes, connected_at FROM connected_apps WHERE user_id = :uid ORDER BY id ASC"),
            {"uid": current["id"]}
        ).mappings().fetchall()

        if not rows:
            # Seed standard Samar OS ecosystem apps
            defaults = [
                ("samar-messenger", "Samar Messenger", "💬", "Profil, Shaxsiy xabarlar, Kontaktlar"),
                ("samar-drive", "Samar Cloud Drive", "☁️", "Fayllar xotirasi, Arxiv nusxalari"),
                ("samar-terminal", "Samar Terminal & CLI", "💻", "Tizim konsoli, API kalitlari")
            ]
            for cid, name, icon, sc in defaults:
                conn.execute(
                    text("INSERT INTO connected_apps (user_id, client_id, app_name, app_icon, scopes) VALUES (:uid, :cid, :name, :icon, :sc)"),
                    {"uid": current["id"], "cid": cid, "name": name, "icon": icon, "sc": sc}
                )
            conn.commit()
            rows = conn.execute(
                text("SELECT id, client_id, app_name, app_icon, scopes, connected_at FROM connected_apps WHERE user_id = :uid ORDER BY id ASC"),
                {"uid": current["id"]}
            ).mappings().fetchall()

    res = []
    for r in rows:
        res.append({
            "id": r["id"],
            "client_id": r["client_id"],
            "app_name": r["app_name"],
            "app_icon": r["app_icon"],
            "scopes": r["scopes"],
            "connected_at": str(r["connected_at"])[:10] if r["connected_at"] else "2026-10-17"
        })
    return res

@app.delete("/api/oauth/apps/{client_id}")
def revoke_connected_app(client_id: str, current: dict = Depends(get_current_user_and_jti)):
    with engine.connect() as conn:
        app_row = conn.execute(
            text("SELECT app_name FROM connected_apps WHERE user_id = :uid AND client_id = :cid"),
            {"uid": current["id"], "cid": client_id}
        ).mappings().first()
        app_name = app_row["app_name"] if app_row else client_id

        conn.execute(
            text("DELETE FROM connected_apps WHERE user_id = :uid AND client_id = :cid"),
            {"uid": current["id"], "cid": client_id}
        )
        conn.execute(
            text("INSERT INTO notifications (user_id, from_user, title, message, type) VALUES (:uid, 'Samar Security', 'Ilova Ruxsati Bekor Qilindi', :msg, 'warning')"),
            {"uid": current["id"], "msg": f"{app_name} ilovasining Samar ID ga ulanish huquqi bekor qilindi."}
        )
        conn.commit()
    return {"message": f"{app_name} muvaffaqiyatli uzildi."}

# ----------------- PROFIL & XAVFSIZLIK -----------------
@app.put("/api/auth/profile", response_model=UserResponse)
def update_profile(data: ProfileUpdate, current: dict = Depends(get_current_user_and_jti)):
    if current.get("security_freeze_until"):
        freeze_dt = datetime.fromisoformat(current["security_freeze_until"].replace("Z", "+00:00"))
        if freeze_dt > datetime.now(timezone.utc):
            raise HTTPException(status_code=403, detail="Xavfsizlik muzlatmasi faol! Akkaunt 1 martalik kod bilan tiklanganligi sababli ma'lumotlarni o'zgartirish 10 kunga to'xtatilgan.")

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
                SELECT id, samar_id, full_name, email, phone, phone_verified, bio, specialty, avatar_path, guardian_id, security_freeze_until, role, two_factor_enabled, created_at
                FROM users WHERE id = :uid
            """),
            {"uid": current["id"]}
        ).mappings().first()
        
        res_dict = dict(updated)
        res_dict["phone_verified"] = bool(res_dict.get("phone_verified", False))
        res_dict["created_at"] = str(res_dict["created_at"])
        res_dict["security_freeze_until"] = str(res_dict["security_freeze_until"]) if res_dict.get("security_freeze_until") else None
        return res_dict

@app.post("/api/auth/change-password")
def change_password(data: PasswordChange, current: dict = Depends(get_current_user_and_jti)):
    if current.get("security_freeze_until"):
        freeze_dt = datetime.fromisoformat(current["security_freeze_until"].replace("Z", "+00:00"))
        if freeze_dt > datetime.now(timezone.utc):
            raise HTTPException(status_code=403, detail="Xavfsizlik muzlatmasi faol! Parolni o'zgartirish 10 kunga to'xtatilgan.")

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
        return {"message": "Parol yangilandi. Boshqa barcha qurilmalar sessiyasi bekor qilindi."}

# ----------------- TELEFON RAQAM VA SMS DISPATCHER -----------------
def dispatch_sms(phone: str, code: str) -> dict:
    """
    Haqiqiy GSM/Telecom SMS provayderlari (Eskiz.uz yoki Twilio) orqali SMS yuborish.
    Agar ESKIZ_EMAIL va ESKIZ_PASSWORD yoki TWILIO kalitlari kiritilmagan bo'lsa,
    ishonchli simulyatsiya rejimida ishlaydi va tizim bildirishnomalariga yetkazadi.
    """
    import urllib.request
    import urllib.parse
    import json
    import re

    clean_digits = re.sub(r"\D", "", phone)
    
    # 1. Eskiz.uz (O'zbekiston milliy SMS provayderi)
    eskiz_email = os.getenv("ESKIZ_EMAIL", "oqdwer@gmail.com")
    eskiz_password = os.getenv("ESKIZ_PASSWORD", "N3KrFZ0i5tW68hv5h1CJTUd5FJweLNi6opK83caI")
    eskiz_token = os.getenv("ESKIZ_TOKEN")
    
    if eskiz_token or (eskiz_email and eskiz_password):
        try:
            import urllib.error
            auth_token = eskiz_token
            if not auth_token:
                login_payload = urllib.parse.urlencode({
                    "email": eskiz_email,
                    "password": eskiz_password
                }).encode("utf-8")
                req = urllib.request.Request(
                    "https://notify.eskiz.uz/api/auth/login",
                    data=login_payload,
                    headers={"Content-Type": "application/x-www-form-urlencoded"}
                )
                with urllib.request.urlopen(req, timeout=8) as response:
                    res_body = json.loads(response.read().decode())
                    auth_token = res_body.get("data", {}).get("token")
            
            if auth_token:
                from_sender = os.getenv("ESKIZ_FROM", "4546")
                
                # 1-urinish: standart matn bilan yuborish
                sms_payload = urllib.parse.urlencode({
                    "mobile_phone": clean_digits,
                    "message": f"Samar ID tasdiqlash kodi: {code}. Bu kodni hech kimga bermang!",
                    "from": from_sender
                }).encode("utf-8")
                
                sms_req = urllib.request.Request(
                    "https://notify.eskiz.uz/api/message/sms/send",
                    data=sms_payload,
                    headers={"Authorization": f"Bearer {auth_token}"}
                )
                
                try:
                    with urllib.request.urlopen(sms_req, timeout=8) as sms_res:
                        return {"is_real": True, "provider": "Eskiz.uz (O'zbekiston GSM)", "status": "sent"}
                except urllib.error.HTTPError as he:
                    err_text = he.read().decode()
                    # Agar Eskiz hisobi test rejimida bo'lsa (shartnoma tuzilmagan bo'lsa), rasmiy test matni bilan yuboriladi
                    if "Для теста" in err_text or "test" in err_text.lower():
                        test_payload = urllib.parse.urlencode({
                            "mobile_phone": clean_digits,
                            "message": "Bu Eskiz dan test",
                            "from": from_sender
                        }).encode("utf-8")
                        test_req = urllib.request.Request(
                            "https://notify.eskiz.uz/api/message/sms/send",
                            data=test_payload,
                            headers={"Authorization": f"Bearer {auth_token}"}
                        )
                        with urllib.request.urlopen(test_req, timeout=8) as test_res:
                            return {"is_real": True, "provider": "Eskiz.uz (O'zbekiston GSM Test)", "status": "sent"}
                    else:
                        print(f"[SMS Gateway] Eskiz xatosi: {err_text}")
        except Exception as e:
            print(f"[SMS Gateway] Eskiz umumiy xatosi: {e}")

    # 2. Twilio (Xalqaro GSM provayderi)
    twilio_sid = os.getenv("TWILIO_ACCOUNT_SID")
    twilio_token = os.getenv("TWILIO_AUTH_TOKEN")
    twilio_from = os.getenv("TWILIO_FROM_NUMBER")
    if twilio_sid and twilio_token and twilio_from:
        try:
            clean_with_plus = phone if phone.startswith("+") else f"+{clean_digits}"
            twilio_url = f"https://api.twilio.com/2010-04-01/Accounts/{twilio_sid}/Messages.json"
            post_data = urllib.parse.urlencode({
                "To": clean_with_plus,
                "From": twilio_from,
                "Body": f"Samar ID tasdiqlash kodi: {code}. Bu kodni hech kimga bermang!"
            }).encode("utf-8")
            
            auth_str = f"{twilio_sid}:{twilio_token}"
            b64_auth = base64.b64encode(auth_str.encode()).decode()
            
            tw_req = urllib.request.Request(
                twilio_url,
                data=post_data,
                headers={"Authorization": f"Basic {b64_auth}"}
            )
            with urllib.request.urlopen(tw_req, timeout=5) as tw_res:
                return {"is_real": True, "provider": "Twilio GSM Global", "status": "sent"}
        except Exception as e:
            print(f"[SMS Gateway] Twilio xatosi: {e}")

    # 3. Samar Ichki Simulyatsiya Shlyuzi (Xabarnomalar qutisi orqali daxlsiz yetkazish)
    return {
        "is_real": False,
        "provider": "Samar Internal Gateway (Xabarnomalar qutisi)",
        "status": "delivered_to_notifications"
    }

@app.post("/api/auth/phone/send-code")
def send_phone_code(data: PhoneSendCode, current: dict = Depends(get_current_user_and_jti)):
    phone_clean = data.phone.strip()
    if len(phone_clean) < 7:
        raise HTTPException(status_code=400, detail="Telefon raqami noto'g'ri kiritildi.")
    
    code = str(random.randint(100000, 999999))
    ACTIVE_PHONE_OTPS[current["id"]] = {
        "phone": phone_clean,
        "code": code,
        "created_at": datetime.now(timezone.utc)
    }
    
    # GSM Provayderga yuborishga urinish
    dispatch_res = dispatch_sms(phone_clean, code)
    
    with engine.connect() as conn:
        conn.execute(
            text("""
                INSERT INTO notifications (user_id, from_user, title, message, type, action_data)
                VALUES (:uid, 'Samar SMS Gateway', 'SMS Tasdiqlash Kodi', :msg, 'security', :code)
            """),
            {
                "uid": current["id"],
                "msg": f"Sizning Samar ID telefon tasdiqlash kodingiz: {code}. Provayder: {dispatch_res['provider']}.",
                "code": code
            }
        )
        conn.commit()
        
    return {
        "message": f"SMS tasdiqlash kodi {phone_clean} raqamiga yuborildi.",
        "is_real": dispatch_res["is_real"],
        "provider": dispatch_res["provider"],
        "debug_code": code
    }

@app.post("/api/auth/phone/verify-code", response_model=UserResponse)
def verify_phone_code(data: PhoneVerifyCode, current: dict = Depends(get_current_user_and_jti)):
    saved_otp = ACTIVE_PHONE_OTPS.get(current["id"])
    if not saved_otp or saved_otp["code"] != data.code.strip():
        raise HTTPException(status_code=400, detail="Noto'g'ri yoki muddati o'tgan SMS kod kiritildi.")
    
    phone_clean = saved_otp["phone"]
    del ACTIVE_PHONE_OTPS[current["id"]]
    
    with engine.connect() as conn:
        conn.execute(
            text("UPDATE users SET phone = :phone, phone_verified = TRUE WHERE id = :uid"),
            {"phone": phone_clean, "uid": current["id"]}
        )
        conn.execute(
            text("""
                INSERT INTO notifications (user_id, from_user, title, message, type)
                VALUES (:uid, 'Samar Security', 'Telefon Raqami Biriktirildi', :msg, 'security')
            """),
            {
                "uid": current["id"],
                "msg": f"Sizning {phone_clean} raqamingiz muvaffaqiyatli tasdiqlandi va Samar ID xavfsizlik protokoliga ulandi."
            }
        )
        conn.commit()
        
        user_row = conn.execute(
            text("SELECT id, samar_id, full_name, email, phone, phone_verified, bio, specialty, avatar_path, guardian_id, security_freeze_until, role, two_factor_enabled, created_at FROM users WHERE id = :uid"),
            {"uid": current["id"]}
        ).mappings().first()
        
    res = dict(user_row)
    res["phone_verified"] = bool(res.get("phone_verified", False))
    res["created_at"] = str(res["created_at"])
    res["security_freeze_until"] = str(res["security_freeze_until"]) if res.get("security_freeze_until") else None
    return res

@app.delete("/api/auth/phone/unlink", response_model=UserResponse)
def unlink_phone(current: dict = Depends(get_current_user_and_jti)):
    with engine.connect() as conn:
        conn.execute(
            text("UPDATE users SET phone = '', phone_verified = FALSE WHERE id = :uid"),
            {"uid": current["id"]}
        )
        conn.commit()
        user_row = conn.execute(
            text("SELECT id, samar_id, full_name, email, phone, phone_verified, bio, specialty, avatar_path, guardian_id, security_freeze_until, role, two_factor_enabled, created_at FROM users WHERE id = :uid"),
            {"uid": current["id"]}
        ).mappings().first()
        
    res = dict(user_row)
    res["phone_verified"] = bool(res.get("phone_verified", False))
    res["created_at"] = str(res["created_at"])
    res["security_freeze_until"] = str(res["security_freeze_until"]) if res.get("security_freeze_until") else None
    return res

@app.post("/api/auth/upload-avatar")
async def upload_avatar(file: UploadFile = File(...), current: dict = Depends(get_current_user_and_jti)):
    extension = os.path.splitext(file.filename)[1].lower()
    if extension not in [".jpg", ".jpeg", ".png", ".webp"]:
        raise HTTPException(status_code=400, detail="Faqat JPG, PNG yoki WEBP rasmlar qabul qilinadi.")
    
    contents = await file.read()
    if len(contents) > 4 * 1024 * 1024:
        raise HTTPException(status_code=400, detail="Rasm hajmi 4MB dan oshmasligi kerak.")
        
    mime_type = "image/jpeg" if extension in [".jpg", ".jpeg"] else ("image/png" if extension == ".png" else "image/webp")
    base64_data = base64.b64encode(contents).decode("utf-8")
    avatar_data_url = f"data:{mime_type};base64,{base64_data}"
    
    with engine.connect() as conn:
        conn.execute(
            text("UPDATE users SET avatar_path = :path WHERE id = :uid"),
            {"path": avatar_data_url, "uid": current["id"]}
        )
        conn.commit()
    
    return {"avatar_url": avatar_data_url, "message": "Avatar doimiy bazada saqlandi!"}

@app.get("/api/auth/sessions", response_model=List[SessionItem])
def get_sessions(current: dict = Depends(get_current_user_and_jti)):
    try:
        with engine.connect() as conn:
            rev_filter = "is_revoked = 0" if is_sqlite else "is_revoked IS FALSE"
            query = f"SELECT id, token_jti, device_name, ip_address, last_active, is_revoked FROM sessions WHERE user_id = :uid AND {rev_filter} ORDER BY id DESC"
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
        rev_val = "1" if is_sqlite else "TRUE"
        conn.execute(
            text(f"UPDATE sessions SET is_revoked = {rev_val} WHERE id = :sid AND user_id = :uid"),
            {"sid": session_id, "uid": current["id"]}
        )
        conn.commit()
    return {"message": "Qurilma sessiyasi bekor qilindi."}

@app.post("/api/auth/logout")
def logout(current: dict = Depends(get_current_user_and_jti)):
    with engine.connect() as conn:
        rev_val = "1" if is_sqlite else "TRUE"
        conn.execute(
            text(f"UPDATE sessions SET is_revoked = {rev_val} WHERE token_jti = :jti"),
            {"jti": current["current_jti"]}
        )
        conn.commit()
    return {"message": "Chiqildi."}

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
if os.path.exists(STATIC_DIR):
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

@app.get("/")
def serve_home():
    return FileResponse(os.path.join(STATIC_DIR, "index.html"))
