import os
import io
import uuid
import mimetypes
from datetime import datetime, timezone, timedelta
from typing import Optional, List

from fastapi import FastAPI, Depends, HTTPException, UploadFile, File, Form, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, Response, StreamingResponse, RedirectResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy import text
try:
    from PIL import Image, ExifTags
    HAS_PILLOW = True
except Exception:
    HAS_PILLOW = False
import httpx
from dotenv import load_dotenv

load_dotenv()

from database import init_db, engine, is_sqlite
from drive_service import drive_manager

app = FastAPI(
    title="Samar Cloud & Moments — Sovereign Cloud Storage",
    description="Samar OS ekotizimining 5 TB hajmli xavfsiz shaxsiy bulut va foto arxiv xizmati.",
    version="1.0.0"
)

app.add_middleware(GZipMiddleware, minimum_size=1000)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

SECRET_KEY = os.getenv("SECRET_KEY", "samar_cloud_super_secret_jwt_key_2026")
SAMAR_ID_URL = os.getenv("SAMAR_ID_URL", "https://samar-id.onrender.com").rstrip("/")
SAMAR_CLOUD_CLIENT_ID = os.getenv("SAMAR_CLOUD_CLIENT_ID", "samar_cloud")
ALGORITHM = "HS256"

security = HTTPBearer(auto_error=False)

# Initialize database
init_db()

# ----------------- JWT & AUTH HELPERS -----------------
def create_access_token(user_id: int, samar_id: str) -> str:
    payload = {
        "sub": str(user_id),
        "samar_id": samar_id,
        "exp": datetime.now(timezone.utc) + timedelta(days=30)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)):
    if not credentials:
        raise HTTPException(status_code=401, detail="Tizimga kirilmagan (Not authenticated)")
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = int(payload.get("sub"))
        samar_id = payload.get("samar_id")
    except (JWTError, ValueError):
        raise HTTPException(status_code=401, detail="Yaroqsiz token (Invalid token)")

    with engine.connect() as conn:
        user = conn.execute(
            text("SELECT id, samar_id, full_name, email, avatar_path FROM users WHERE id = :uid"),
            {"uid": user_id}
        ).mappings().first()

    if not user:
        raise HTTPException(status_code=404, detail="Foydalanuvchi topilmadi")
    return dict(user)

def extract_exif(image_bytes: bytes) -> dict:
    """Extracts camera model, taken date, and dimensions using Pillow or pure Python fallback."""
    meta = {"camera": None, "date": None, "width": None, "height": None}
    if HAS_PILLOW:
        try:
            img = Image.open(io.BytesIO(image_bytes))
            meta["width"], meta["height"] = img.size
            exif = img._getexif()
            if exif:
                exif_dict = {ExifTags.TAGS.get(k, k): v for k, v in exif.items() if k in ExifTags.TAGS}
                make = exif_dict.get("Make", "")
                model = exif_dict.get("Model", "")
                if model:
                    meta["camera"] = f"{make} {model}".strip()
                date_taken = exif_dict.get("DateTimeOriginal") or exif_dict.get("DateTime")
                if date_taken:
                    meta["date"] = str(date_taken)
            return meta
        except Exception:
            pass

    # Pure Python binary fallback for dimensions
    try:
        import struct
        if image_bytes.startswith(b'\x89PNG\r\n\x1a\n') and len(image_bytes) >= 24:
            meta["width"], meta["height"] = struct.unpack('>II', image_bytes[16:24])
        elif image_bytes.startswith(b'\xff\xd8'):
            idx = 2
            length = len(image_bytes)
            while idx < length - 8:
                if image_bytes[idx] != 0xff:
                    idx += 1
                    continue
                marker = image_bytes[idx + 1]
                if marker in [0xc0, 0xc1, 0xc2]:
                    h, w = struct.unpack('>HH', image_bytes[idx+5:idx+9])
                    meta["width"], meta["height"] = w, h
                    break
                else:
                    seg_len = struct.unpack('>H', image_bytes[idx+2:idx+4])[0]
                    idx += 2 + seg_len
    except Exception:
        pass
    return meta

def detect_category(mime_type: str, filename: str) -> str:
    ext = filename.lower().split('.')[-1] if '.' in filename else ''
    if mime_type.startswith("image/") or ext in ["jpg", "jpeg", "png", "webp", "gif", "heic", "raw"]:
        return "image"
    if mime_type.startswith("video/") or ext in ["mp4", "mkv", "mov", "avi", "webm"]:
        return "video"
    if mime_type.startswith("audio/") or ext in ["mp3", "wav", "m4a", "flac", "ogg"]:
        return "audio"
    if ext in ["pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "md"]:
        return "document"
    if ext in ["zip", "rar", "7z", "tar", "gz"]:
        return "archive"
    if ext in ["py", "js", "html", "css", "json", "ts", "cpp", "c", "java", "sql"]:
        return "code"
    return "other"

# ----------------- SAMAR ID SSO AUTH -----------------
@app.post("/api/auth/sso/callback")
async def sso_callback(data: dict):
    code = data.get("code")
    redirect_uri = data.get("redirect_uri")
    if not code:
        raise HTTPException(status_code=400, detail="Avtorizatsiya kodi (code) yuborilmadi.")

    async with httpx.AsyncClient() as client:
        # 1. Exchange code for Samar ID access token
        try:
            token_res = await client.post(
                f"{SAMAR_ID_URL}/api/oauth/token",
                json={
                    "code": code,
                    "client_id": SAMAR_CLOUD_CLIENT_ID,
                    "redirect_uri": redirect_uri,
                    "grant_type": "authorization_code"
                },
                timeout=10.0
            )
            if token_res.status_code != 200:
                raise HTTPException(status_code=400, detail="Samar ID dan token olishda xatolik: " + token_res.text)
            token_data = token_res.json()
            samar_token = token_data.get("access_token")

            # 2. Get user info
            user_res = await client.get(
                f"{SAMAR_ID_URL}/api/oauth/userinfo",
                headers={"Authorization": f"Bearer {samar_token}"},
                timeout=10.0
            )
            if user_res.status_code != 200:
                raise HTTPException(status_code=400, detail="Foydalanuvchi ma'lumotlarini yuklashda xatolik")
            user_data = user_res.json()
        except httpx.RequestError as e:
            raise HTTPException(status_code=502, detail=f"Samar ID serveriga ulanib bo'lmadi: {e}")

    # 3. Upsert into Samar Cloud local users database
    samar_id = user_data["samar_id"]
    full_name = user_data.get("full_name") or samar_id
    email = user_data.get("email") or ""
    avatar_path = user_data.get("avatar_path") or ""

    with engine.connect() as conn:
        existing = conn.execute(
            text("SELECT id, samar_id, full_name, email, avatar_path FROM users WHERE samar_id = :sid"),
            {"sid": samar_id}
        ).mappings().first()

        if existing:
            user_id = existing["id"]
            conn.execute(
                text("UPDATE users SET full_name = :fn, email = :em, avatar_path = :av WHERE id = :id"),
                {"fn": full_name, "em": email, "av": avatar_path, "id": user_id}
            )
        else:
            if is_sqlite:
                res = conn.execute(
                    text("INSERT INTO users (samar_id, full_name, email, avatar_path) VALUES (:sid, :fn, :em, :av)"),
                    {"sid": samar_id, "fn": full_name, "em": email, "av": avatar_path}
                )
                user_id = res.lastrowid
            else:
                res = conn.execute(
                    text("INSERT INTO users (samar_id, full_name, email, avatar_path) VALUES (:sid, :fn, :em, :av) RETURNING id"),
                    {"sid": samar_id, "fn": full_name, "em": email, "av": avatar_path}
                ).first()
                user_id = res[0]
        conn.commit()

    # 4. Generate Samar Cloud session token
    cloud_token = create_access_token(user_id, samar_id)
    return {
        "access_token": cloud_token,
        "token_type": "bearer",
        "user": {
            "id": user_id,
            "samar_id": samar_id,
            "full_name": full_name,
            "email": email,
            "avatar_path": avatar_path
        }
    }

@app.get("/api/auth/me")
def get_me(user: dict = Depends(get_current_user)):
    return user

# ----------------- GOOGLE DRIVE 5TB STATUS & SETUP -----------------
@app.get("/api/drive/status")
def get_drive_status(request: Request, user: dict = Depends(get_current_user)):
    status = drive_manager.get_storage_quota()
    if not status.get("connected"):
        redirect_uri = str(request.base_url).rstrip("/") + "/api/drive/callback"
        try:
            status["auth_url"] = drive_manager.get_auth_url(redirect_uri)
        except Exception:
            status["auth_url"] = None
    return status

@app.get("/api/drive/connect")
def connect_drive(request: Request):
    redirect_uri = str(request.base_url).rstrip("/") + "/api/drive/callback"
    auth_url = drive_manager.get_auth_url(redirect_uri)
    return RedirectResponse(auth_url)

@app.get("/api/drive/callback")
def drive_oauth_callback(code: str, request: Request):
    redirect_uri = str(request.base_url).rstrip("/") + "/api/drive/callback"
    try:
        drive_manager.complete_auth(code, redirect_uri)
        return RedirectResponse("/?drive_connected=success")
    except Exception as e:
        return RedirectResponse(f"/?drive_error={str(e)}")

# ----------------- FOLDERS APIS -----------------
@app.get("/api/folders")
def get_folders(parent_id: Optional[int] = None, user: dict = Depends(get_current_user)):
    with engine.connect() as conn:
        if parent_id is None:
            rows = conn.execute(
                text("SELECT id, name, color, created_at FROM folders WHERE user_id = :uid AND parent_id IS NULL AND is_trashed = 0 ORDER BY name ASC"),
                {"uid": user["id"]}
            ).mappings().all()
        else:
            rows = conn.execute(
                text("SELECT id, name, color, created_at FROM folders WHERE user_id = :uid AND parent_id = :pid AND is_trashed = 0 ORDER BY name ASC"),
                {"uid": user["id"], "pid": parent_id}
            ).mappings().all()
    return [dict(r) for r in rows]

@app.post("/api/folders")
def create_folder(data: dict, user: dict = Depends(get_current_user)):
    name = data.get("name", "").strip()
    if not name:
        raise HTTPException(status_code=400, detail="Papka nomi bo'sh bo'lishi mumkin emas")
    parent_id = data.get("parent_id")
    color = data.get("color", "#00f2fe")

    with engine.connect() as conn:
        if is_sqlite:
            res = conn.execute(
                text("INSERT INTO folders (user_id, parent_id, name, color) VALUES (:uid, :pid, :name, :col)"),
                {"uid": user["id"], "pid": parent_id, "name": name, "col": color}
            )
            folder_id = res.lastrowid
        else:
            res = conn.execute(
                text("INSERT INTO folders (user_id, parent_id, name, color) VALUES (:uid, :pid, :name, :col) RETURNING id"),
                {"uid": user["id"], "pid": parent_id, "name": name, "col": color}
            ).first()
            folder_id = res[0]
        conn.commit()

    return {"id": folder_id, "name": name, "color": color, "parent_id": parent_id}

# ----------------- FILES APIS -----------------
@app.get("/api/files")
def get_files(
    folder_id: Optional[int] = None,
    category: Optional[str] = None,
    is_favorite: Optional[bool] = None,
    is_trashed: Optional[bool] = False,
    search: Optional[str] = None,
    user: dict = Depends(get_current_user)
):
    query_str = "SELECT id, folder_id, name, original_name, file_type, category, size, drive_file_id, thumbnail_url, is_favorite, is_trashed, exif_camera, exif_date, width, height, created_at FROM files WHERE user_id = :uid"
    params = {"uid": user["id"]}

    if is_trashed is not None:
        query_str += " AND is_trashed = :trash"
        params["trash"] = 1 if is_trashed else 0

    if folder_id is not None and not is_trashed:
        query_str += " AND folder_id = :fid"
        params["fid"] = folder_id
    elif folder_id is None and not is_trashed and not category and is_favorite is None and not search:
        query_str += " AND folder_id IS NULL"

    if category:
        query_str += " AND category = :cat"
        params["cat"] = category

    if is_favorite:
        query_str += " AND is_favorite = 1"

    if search:
        query_str += " AND name LIKE :q"
        params["q"] = f"%{search}%"

    query_str += " ORDER BY id DESC"

    with engine.connect() as conn:
        rows = conn.execute(text(query_str), params).mappings().all()

    return [dict(r) for r in rows]

@app.post("/api/files/upload")
async def upload_file(
    file: UploadFile = File(...),
    folder_id: Optional[int] = Form(None),
    user: dict = Depends(get_current_user)
):
    content = await file.read()
    filename = file.filename or "fayl_" + str(uuid.uuid4())[:8]
    size = len(content)
    mime_type = file.content_type or mimetypes.guess_type(filename)[0] or "application/octet-stream"
    category = detect_category(mime_type, filename)

    # Extract EXIF if image
    exif = {}
    if category == "image":
        exif = extract_exif(content)

    # Upload to 5TB Google Drive
    upload_res = drive_manager.upload_file(content, filename, mime_type)

    with engine.connect() as conn:
        insert_query = """
        INSERT INTO files (
            user_id, folder_id, name, original_name, file_type, category, size,
            drive_file_id, storage_path, thumbnail_url, exif_camera, exif_date, width, height
        ) VALUES (
            :uid, :fid, :name, :orig, :ftype, :cat, :sz,
            :did, :spath, :thumb, :cam, :dt, :w, :h
        )
        """
        params = {
            "uid": user["id"],
            "fid": folder_id,
            "name": filename,
            "orig": filename,
            "ftype": mime_type,
            "cat": category,
            "sz": size,
            "did": upload_res.get("drive_file_id"),
            "spath": upload_res.get("storage_path"),
            "thumb": upload_res.get("thumbnail_link"),
            "cam": exif.get("camera"),
            "dt": exif.get("date"),
            "w": exif.get("width"),
            "h": exif.get("height")
        }

        if is_sqlite:
            res = conn.execute(text(insert_query), params)
            file_id = res.lastrowid
        else:
            res = conn.execute(text(insert_query + " RETURNING id"), params).first()
            file_id = res[0]
        conn.commit()

    return {
        "id": file_id,
        "name": filename,
        "size": size,
        "file_type": mime_type,
        "category": category,
        "drive_file_id": upload_res.get("drive_file_id"),
        "thumbnail_url": upload_res.get("thumbnail_link"),
        "created_at": datetime.now(timezone.utc).isoformat()
    }

@app.post("/api/files/{file_id}/favorite")
def toggle_favorite(file_id: int, user: dict = Depends(get_current_user)):
    with engine.connect() as conn:
        f = conn.execute(
            text("SELECT id, is_favorite FROM files WHERE id = :id AND user_id = :uid"),
            {"id": file_id, "uid": user["id"]}
        ).mappings().first()
        if not f:
            raise HTTPException(status_code=404, detail="Fayl topilmadi")
        new_fav = 0 if f["is_favorite"] else 1
        conn.execute(
            text("UPDATE files SET is_favorite = :fav WHERE id = :id"),
            {"fav": new_fav, "id": file_id}
        )
        conn.commit()
    return {"id": file_id, "is_favorite": bool(new_fav)}

@app.delete("/api/files/{file_id}")
def delete_file(file_id: int, permanent: bool = False, user: dict = Depends(get_current_user)):
    with engine.connect() as conn:
        f = conn.execute(
            text("SELECT id, drive_file_id, storage_path, is_trashed FROM files WHERE id = :id AND user_id = :uid"),
            {"id": file_id, "uid": user["id"]}
        ).mappings().first()
        if not f:
            raise HTTPException(status_code=404, detail="Fayl topilmadi")

        if not permanent and not f["is_trashed"]:
            # Move to trash
            conn.execute(text("UPDATE files SET is_trashed = 1 WHERE id = :id"), {"id": file_id})
            conn.commit()
            return {"message": "Fayl savatga ko'chirildi", "is_trashed": True}
        else:
            # Permanent delete
            if f.get("drive_file_id"):
                drive_manager.delete_file(f["drive_file_id"])
            if f.get("storage_path") and os.path.exists(f["storage_path"]):
                try:
                    os.remove(f["storage_path"])
                except Exception:
                    pass
            conn.execute(text("DELETE FROM files WHERE id = :id"), {"id": file_id})
            conn.commit()
            return {"message": "Fayl butunlay o'chirildi", "deleted": True}

@app.post("/api/files/{file_id}/restore")
def restore_file(file_id: int, user: dict = Depends(get_current_user)):
    with engine.connect() as conn:
        conn.execute(
            text("UPDATE files SET is_trashed = 0 WHERE id = :id AND user_id = :uid"),
            {"id": file_id, "uid": user["id"]}
        )
        conn.commit()
    return {"message": "Fayl tiklandi", "is_trashed": False}

@app.get("/api/files/{file_id}/stream")
def stream_file(file_id: int, user: dict = Depends(get_current_user)):
    with engine.connect() as conn:
        f = conn.execute(
            text("SELECT id, name, file_type, size, drive_file_id, storage_path FROM files WHERE id = :id AND user_id = :uid"),
            {"id": file_id, "uid": user["id"]}
        ).mappings().first()
    if not f:
        raise HTTPException(status_code=404, detail="Fayl topilmadi")

    if f.get("drive_file_id") and drive_manager.is_connected():
        try:
            content = drive_manager.download_file(f["drive_file_id"])
            return Response(content=content, media_type=f["file_type"])
        except Exception as e:
            print(f"[Stream] Drive error: {e}")

    if f.get("storage_path") and os.path.exists(f["storage_path"]):
        return FileResponse(f["storage_path"], media_type=f["file_type"])

    raise HTTPException(status_code=404, detail="Fayl tarkibi topilmadi")

@app.get("/api/files/{file_id}/download")
def download_file(file_id: int, user: dict = Depends(get_current_user)):
    with engine.connect() as conn:
        f = conn.execute(
            text("SELECT id, name, file_type, size, drive_file_id, storage_path FROM files WHERE id = :id AND user_id = :uid"),
            {"id": file_id, "uid": user["id"]}
        ).mappings().first()
    if not f:
        raise HTTPException(status_code=404, detail="Fayl topilmadi")

    if f.get("drive_file_id") and drive_manager.is_connected():
        try:
            content = drive_manager.download_file(f["drive_file_id"])
            return Response(
                content=content,
                media_type="application/octet-stream",
                headers={"Content-Disposition": f'attachment; filename="{f["name"]}"'}
            )
        except Exception as e:
            print(f"[Download] Drive error: {e}")

    if f.get("storage_path") and os.path.exists(f["storage_path"]):
        return FileResponse(
            f["storage_path"],
            filename=f["name"],
            media_type="application/octet-stream"
        )

    raise HTTPException(status_code=404, detail="Fayl yuklab olish uchun topilmadi")

# ----------------- SAMAR MOMENTS (PHOTO GALLERY & TIMELINE) -----------------
@app.get("/api/moments")
def get_moments(user: dict = Depends(get_current_user)):
    """Returns photos and videos grouped chronologically into Apple-style Moments."""
    with engine.connect() as conn:
        rows = conn.execute(
            text("""
            SELECT id, name, original_name, file_type, category, size, drive_file_id, thumbnail_url,
                   is_favorite, exif_camera, exif_date, width, height, created_at
            FROM files
            WHERE user_id = :uid AND category IN ('image', 'video') AND is_trashed = 0
            ORDER BY id DESC
            """),
            {"uid": user["id"]}
        ).mappings().all()

    # Chronological grouping
    groups = {}
    for r in rows:
        d_str = str(r.get("exif_date") or r.get("created_at") or "")
        try:
            # Parse date
            dt = datetime.fromisoformat(d_str.replace(" ", "T").split(".")[0])
            group_key = dt.strftime("%B %Y") # e.g. "October 2026"
        except Exception:
            group_key = "Boshqa Lahzalar"

        if group_key not in groups:
            groups[group_key] = []
        groups[group_key].append(dict(r))

    return [{"group_title": k, "items": v} for k, v in groups.items()]

# ----------------- PWA & STATIC MOUNT -----------------
STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
if os.path.exists(STATIC_DIR):
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

@app.get("/")
def serve_home():
    return FileResponse(os.path.join(STATIC_DIR, "index.html"))

@app.get("/manifest.json")
def get_manifest():
    return FileResponse(os.path.join(STATIC_DIR, "manifest.json"), media_type="application/manifest+json")

@app.get("/sw.js")
def get_sw():
    return FileResponse(os.path.join(STATIC_DIR, "sw.js"), media_type="application/javascript", headers={"Service-Worker-Allowed": "/"})
