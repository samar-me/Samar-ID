import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "samar_id.db")

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    cursor = conn.cursor()
    
    # 1. Foydalanuvchilar jadvali (kengaytirilgan)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        samar_id TEXT UNIQUE NOT NULL,       -- e.g. @username.samar
        full_name TEXT NOT NULL,
        email TEXT UNIQUE,
        phone TEXT,
        bio TEXT DEFAULT '',
        specialty TEXT DEFAULT 'Developer',  -- Kasb / Roli
        password_hash TEXT NOT NULL,
        avatar_path TEXT DEFAULT '',
        pin_code TEXT DEFAULT '',           -- 6 xonali xavfsizlik PIN kodi
        two_factor_enabled BOOLEAN DEFAULT 0,
        role TEXT DEFAULT 'citizen',        -- citizen, developer, admin
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        is_active BOOLEAN DEFAULT 1
    );
    """)
    
    # 2. Faol sessiyalar va ulangan qurilmalar jadvali (Device Sessions)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        token_jti TEXT UNIQUE NOT NULL,      -- Tokenning unikal identifikatori
        device_name TEXT NOT NULL,           -- masalan: Windows 11 / Samar OS Desktop / Pixel 7
        ip_address TEXT,
        last_active TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        is_revoked BOOLEAN DEFAULT 0,
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
    );
    """)

    # 3. Samar Ekotizim Ilovalari (OAuth2 Apps: Samar Chat, Cloud, AI va h.k.)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS ecosystem_apps (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        client_id TEXT UNIQUE NOT NULL,      -- masalan: samar_chat_app
        client_name TEXT NOT NULL,           -- Samar Chat
        client_secret TEXT NOT NULL,
        redirect_uri TEXT NOT NULL,
        app_icon TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)
    
    conn.commit()
    conn.close()
