import os
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

# Neon PostgreSQL yoki lokal SQLite
DATABASE_URL = os.getenv("DATABASE_URL", "")

# SQLAlchemy 2.0 uchun psycopg2 prefiksini to'g'rilash
if DATABASE_URL.startswith("postgresql://"):
    DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+psycopg2://", 1)
elif DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql+psycopg2://", 1)

if not DATABASE_URL:
    DB_PATH = os.path.join(os.path.dirname(__file__), "samar_id.db")
    DATABASE_URL = f"sqlite:///{DB_PATH}"

is_sqlite = DATABASE_URL.startswith("sqlite")

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if is_sqlite else {}
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
            CREATE TABLE IF NOT EXISTS ecosystem_apps (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                client_id TEXT UNIQUE NOT NULL,
                client_name TEXT NOT NULL,
                client_secret TEXT NOT NULL,
                redirect_uri TEXT NOT NULL,
                app_icon TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            """))
        else:
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
                role VARCHAR(50) DEFAULT 'citizen',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_active BOOLEAN DEFAULT TRUE
            );
            """))
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
            CREATE TABLE IF NOT EXISTS ecosystem_apps (
                id SERIAL PRIMARY KEY,
                client_id VARCHAR(100) UNIQUE NOT NULL,
                client_name VARCHAR(150) NOT NULL,
                client_secret TEXT NOT NULL,
                redirect_uri TEXT NOT NULL,
                app_icon TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            """))
        conn.commit()

def get_connection():
    return engine.connect()
