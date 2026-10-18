import os
from sqlalchemy import create_engine, text
from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./samar_cloud.db")

# Neon Postgres fix if postgres:// is passed
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

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

def init_db():
    with engine.connect() as conn:
        if is_sqlite:
            # SQLite Schemas
            conn.execute(text("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                samar_id TEXT UNIQUE NOT NULL,
                full_name TEXT NOT NULL,
                email TEXT,
                avatar_path TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            """))

            conn.execute(text("""
            CREATE TABLE IF NOT EXISTS folders (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                parent_id INTEGER,
                name TEXT NOT NULL,
                color TEXT DEFAULT '#00f2fe',
                is_trashed INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
                FOREIGN KEY (parent_id) REFERENCES folders (id) ON DELETE CASCADE
            );
            """))

            conn.execute(text("""
            CREATE TABLE IF NOT EXISTS files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                folder_id INTEGER,
                name TEXT NOT NULL,
                original_name TEXT NOT NULL,
                file_type TEXT NOT NULL,
                category TEXT DEFAULT 'document',
                size INTEGER NOT NULL,
                drive_file_id TEXT,
                storage_path TEXT,
                thumbnail_url TEXT,
                is_favorite INTEGER DEFAULT 0,
                is_trashed INTEGER DEFAULT 0,
                exif_camera TEXT,
                exif_date TEXT,
                width INTEGER,
                height INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
                FOREIGN KEY (folder_id) REFERENCES folders (id) ON DELETE SET NULL
            );
            """))

            conn.execute(text("""
            CREATE TABLE IF NOT EXISTS shares (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                share_token TEXT UNIQUE NOT NULL,
                is_public INTEGER DEFAULT 1,
                password_hash TEXT,
                expires_at TIMESTAMP,
                views_count INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (file_id) REFERENCES files (id) ON DELETE CASCADE,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
            );
            """))

            conn.execute(text("""
            CREATE TABLE IF NOT EXISTS cloud_settings (
                key TEXT PRIMARY KEY,
                value TEXT
            );
            """))
        else:
            # PostgreSQL Schemas
            conn.execute(text("""
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                samar_id VARCHAR(100) UNIQUE NOT NULL,
                full_name VARCHAR(150) NOT NULL,
                email VARCHAR(150),
                avatar_path TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            """))

            conn.execute(text("""
            CREATE TABLE IF NOT EXISTS folders (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
                parent_id INTEGER REFERENCES folders (id) ON DELETE CASCADE,
                name VARCHAR(255) NOT NULL,
                color VARCHAR(50) DEFAULT '#00f2fe',
                is_trashed INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            """))

            conn.execute(text("""
            CREATE TABLE IF NOT EXISTS files (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
                folder_id INTEGER REFERENCES folders (id) ON DELETE SET NULL,
                name VARCHAR(255) NOT NULL,
                original_name VARCHAR(255) NOT NULL,
                file_type VARCHAR(100) NOT NULL,
                category VARCHAR(50) DEFAULT 'document',
                size BIGINT NOT NULL,
                drive_file_id VARCHAR(255),
                storage_path TEXT,
                thumbnail_url TEXT,
                is_favorite INTEGER DEFAULT 0,
                is_trashed INTEGER DEFAULT 0,
                exif_camera VARCHAR(150),
                exif_date VARCHAR(100),
                width INTEGER,
                height INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            """))

            conn.execute(text("""
            CREATE TABLE IF NOT EXISTS shares (
                id SERIAL PRIMARY KEY,
                file_id INTEGER NOT NULL REFERENCES files (id) ON DELETE CASCADE,
                user_id INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
                share_token VARCHAR(120) UNIQUE NOT NULL,
                is_public INTEGER DEFAULT 1,
                password_hash TEXT,
                expires_at TIMESTAMP,
                views_count INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            """))

            conn.execute(text("""
            CREATE TABLE IF NOT EXISTS cloud_settings (
                key VARCHAR(100) PRIMARY KEY,
                value TEXT
            );
            """))

        conn.commit()

def get_connection():
    return engine.connect()
