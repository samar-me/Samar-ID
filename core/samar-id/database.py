import os
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

# Neon PostgreSQL yoki lokal SQLite
DATABASE_URL = os.getenv("DATABASE_URL", "")

if DATABASE_URL.startswith("postgresql://"):
    DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+psycopg2://", 1)
elif DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql+psycopg2://", 1)

if not DATABASE_URL:
    DB_PATH = os.path.join(os.path.dirname(__file__), "samar_id.db")
    DATABASE_URL = f"sqlite:///{DB_PATH}"

is_sqlite = DATABASE_URL.startswith("sqlite")

if is_sqlite:
    engine = create_engine(
        DATABASE_URL,
        connect_args={"check_same_thread": False}
    )
else:
    engine = create_engine(
        DATABASE_URL,
        pool_pre_ping=True,
        pool_recycle=300,
        pool_size=10,
        max_overflow=20
    )

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def init_db():
    with engine.connect() as conn:
        if is_sqlite:
            conn.execute(text("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                samar_id TEXT UNIQUE NOT NULL,
                full_name TEXT NOT NULL,
                email TEXT UNIQUE,
                phone TEXT,
                bio TEXT DEFAULT '',
                specialty TEXT DEFAULT 'Developer',
                password_hash TEXT NOT NULL,
                avatar_path TEXT DEFAULT '',
                pin_code TEXT DEFAULT '',
                two_factor_enabled BOOLEAN DEFAULT 0,
                guardian_id TEXT DEFAULT '',              -- Ishonchli do'st
                security_freeze_until TIMESTAMP,          -- 10 kunlik muzlatish
                role TEXT DEFAULT 'citizen',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_active BOOLEAN DEFAULT 1
            );
            """))
            conn.execute(text("""
            CREATE TABLE IF NOT EXISTS sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                token_jti TEXT UNIQUE NOT NULL,
                device_name TEXT NOT NULL,
                ip_address TEXT,
                last_active TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_revoked BOOLEAN DEFAULT 0,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
            );
            """))
            conn.execute(text("""
            CREATE TABLE IF NOT EXISTS qr_logins (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                qr_token TEXT UNIQUE NOT NULL,
                status TEXT DEFAULT 'pending',          -- pending, approved, expired
                user_id INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            """))
            conn.execute(text("""
            CREATE TABLE IF NOT EXISTS notifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                from_user TEXT DEFAULT 'Samar Security',
                title TEXT NOT NULL,
                message TEXT NOT NULL,
                type TEXT DEFAULT 'info',
                is_read BOOLEAN DEFAULT 0,
                action_data TEXT DEFAULT '',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
            );
            """))
            conn.execute(text("""
            CREATE TABLE IF NOT EXISTS recovery_codes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                code_hash TEXT NOT NULL,
                code_preview TEXT NOT NULL,
                is_used BOOLEAN DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
            );
            """))
            conn.execute(text("""
            CREATE TABLE IF NOT EXISTS connected_apps (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                client_id TEXT NOT NULL,
                app_name TEXT NOT NULL,
                app_icon TEXT DEFAULT '📱',
                scopes TEXT DEFAULT 'profile,email',
                connected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
            );
            """))
            conn.execute(text("""
            CREATE TABLE IF NOT EXISTS passkey_credentials (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                credential_id TEXT UNIQUE NOT NULL,
                public_key TEXT,
                device_name TEXT DEFAULT 'Apple Face ID',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
            );
            """))
            conn.execute(text("""
            CREATE TABLE IF NOT EXISTS oauth_codes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                code TEXT UNIQUE NOT NULL,
                client_id TEXT NOT NULL,
                user_id INTEGER NOT NULL,
                redirect_uri TEXT NOT NULL,
                scopes TEXT DEFAULT 'profile,email',
                expires_at TIMESTAMP NOT NULL,
                is_used INTEGER DEFAULT 0,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
            );
            """))
            # SQLite table migrations
            try:
                existing_cols = [row[1] for row in conn.execute(text("PRAGMA table_info(users)")).fetchall()]
                if existing_cols:
                    if "phone" not in existing_cols:
                        conn.execute(text("ALTER TABLE users ADD COLUMN phone TEXT DEFAULT '';"))
                    if "phone_verified" not in existing_cols:
                        conn.execute(text("ALTER TABLE users ADD COLUMN phone_verified BOOLEAN DEFAULT 0;"))
                    if "bio" not in existing_cols:
                        conn.execute(text("ALTER TABLE users ADD COLUMN bio TEXT DEFAULT '';"))
                    if "specialty" not in existing_cols:
                        conn.execute(text("ALTER TABLE users ADD COLUMN specialty TEXT DEFAULT 'Developer';"))
                    if "avatar_path" not in existing_cols:
                        conn.execute(text("ALTER TABLE users ADD COLUMN avatar_path TEXT DEFAULT '';"))
                    if "guardian_id" not in existing_cols:
                        conn.execute(text("ALTER TABLE users ADD COLUMN guardian_id TEXT DEFAULT '';"))
                    if "security_freeze_until" not in existing_cols:
                        conn.execute(text("ALTER TABLE users ADD COLUMN security_freeze_until TIMESTAMP;"))
                    if "two_factor_enabled" not in existing_cols:
                        conn.execute(text("ALTER TABLE users ADD COLUMN two_factor_enabled BOOLEAN DEFAULT 0;"))
            except Exception:
                pass
        else:
            # PostgreSQL (Neon Cloud)
            conn.execute(text("""
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                samar_id VARCHAR(100) UNIQUE NOT NULL,
                full_name VARCHAR(150) NOT NULL,
                email VARCHAR(255) UNIQUE,
                phone VARCHAR(50),
                bio TEXT DEFAULT '',
                specialty VARCHAR(100) DEFAULT 'Developer',
                password_hash TEXT NOT NULL,
                avatar_path TEXT DEFAULT '',
                pin_code VARCHAR(10) DEFAULT '',
                two_factor_enabled BOOLEAN DEFAULT FALSE,
                guardian_id VARCHAR(100) DEFAULT '',
                security_freeze_until TIMESTAMP,
                role VARCHAR(50) DEFAULT 'citizen',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_active BOOLEAN DEFAULT TRUE,
                phone_verified BOOLEAN DEFAULT FALSE
            );
            """))
            # Agar ustunlar avvalgi bazada yo'q bo'lsa qo'shish
            conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS phone VARCHAR(50);"))
            conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS bio TEXT DEFAULT '';"))
            conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS specialty VARCHAR(100) DEFAULT 'Developer';"))
            conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar_path TEXT DEFAULT '';"))
            conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS guardian_id VARCHAR(100) DEFAULT '';"))
            conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS security_freeze_until TIMESTAMP;"))
            conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS phone_verified BOOLEAN DEFAULT FALSE;"))
            
            conn.execute(text("""
            CREATE TABLE IF NOT EXISTS sessions (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
                token_jti VARCHAR(100) UNIQUE NOT NULL,
                device_name VARCHAR(100) NOT NULL,
                ip_address VARCHAR(50),
                last_active TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_revoked BOOLEAN DEFAULT FALSE
            );
            """))
            conn.execute(text("""
            CREATE TABLE IF NOT EXISTS qr_logins (
                id SERIAL PRIMARY KEY,
                qr_token VARCHAR(100) UNIQUE NOT NULL,
                status VARCHAR(20) DEFAULT 'pending',
                user_id INTEGER REFERENCES users (id) ON DELETE CASCADE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            """))
            conn.execute(text("""
            CREATE TABLE IF NOT EXISTS notifications (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
                from_user VARCHAR(100) DEFAULT 'Samar Security',
                title VARCHAR(200) NOT NULL,
                message TEXT NOT NULL,
                type VARCHAR(50) DEFAULT 'info',
                is_read BOOLEAN DEFAULT FALSE,
                action_data TEXT DEFAULT '',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            """))
            conn.execute(text("""
            CREATE TABLE IF NOT EXISTS recovery_codes (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
                code_hash VARCHAR(255) NOT NULL,
                code_preview VARCHAR(50) NOT NULL,
                is_used BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            """))
            conn.execute(text("""
            CREATE TABLE IF NOT EXISTS connected_apps (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
                client_id VARCHAR(100) NOT NULL,
                app_name VARCHAR(150) NOT NULL,
                app_icon VARCHAR(50) DEFAULT '📱',
                scopes VARCHAR(255) DEFAULT 'profile,email',
                connected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            """))
            conn.execute(text("""
            CREATE TABLE IF NOT EXISTS passkey_credentials (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
                credential_id VARCHAR(255) UNIQUE NOT NULL,
                public_key TEXT,
                device_name VARCHAR(150) DEFAULT 'Apple Face ID',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            """))
            conn.execute(text("""
            CREATE TABLE IF NOT EXISTS oauth_codes (
                id SERIAL PRIMARY KEY,
                code VARCHAR(120) UNIQUE NOT NULL,
                client_id VARCHAR(100) NOT NULL,
                user_id INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
                redirect_uri TEXT NOT NULL,
                scopes VARCHAR(255) DEFAULT 'profile,email',
                expires_at TIMESTAMP NOT NULL,
                is_used INTEGER DEFAULT 0
            );
            """))
        conn.commit()

def get_connection():
    return engine.connect()
