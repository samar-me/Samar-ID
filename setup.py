import os
import sys
import subprocess
import shutil

print("=" * 60)
print("       SAMAR OS HOME SERVER - SOZLASH VA O'RNATISH")
print("=" * 60)

base_dir = os.path.dirname(os.path.abspath(__file__))
venv_dir = os.path.join(base_dir, ".venv")
venv_python = os.path.join(venv_dir, "Scripts", "python.exe")

# 1. Virtual environment
if not os.path.exists(venv_python):
    print("\n[1/4] Virtual muhit (.venv) yaratilmoqda...")
    subprocess.check_call([sys.executable, "-m", "venv", venv_dir])
    print("[OK] Virtual muhit yaratildi.")
else:
    print("\n[1/4] Virtual muhit (.venv) allaqachon mavjud.")

# 2. Upgrade pip
subprocess.check_call([venv_python, "-m", "pip", "install", "--upgrade", "pip", "--quiet"])

# 3. Requirements for Samar Cloud and Samar ID
print("\n[2/4] Samar Cloud kutubxonalari o'rnatilmoqda...")
req_cloud = os.path.join(base_dir, "core", "samar-cloud", "requirements.txt")
subprocess.check_call([venv_python, "-m", "pip", "install", "-r", req_cloud, "--quiet"])

print("\n[3/4] Samar ID kutubxonalari o'rnatilmoqda...")
req_id = os.path.join(base_dir, "core", "samar-id", "requirements.txt")
subprocess.check_call([venv_python, "-m", "pip", "install", "-r", req_id, "--quiet"])
print("[OK] Barcha kutubxonalar o'rnatildi.")

# 4. Environment & folders
print("\n[4/4] Sozlamalar va papkalar tekshirilmoqda...")
cloud_env = os.path.join(base_dir, "core", "samar-cloud", ".env")
cloud_env_ex = os.path.join(base_dir, "core", "samar-cloud", ".env.example")
if not os.path.exists(cloud_env) and os.path.exists(cloud_env_ex):
    shutil.copy(cloud_env_ex, cloud_env)
    print("[OK] Samar Cloud .env yaratildi.")

id_env = os.path.join(base_dir, "core", "samar-id", ".env")
id_env_ex = os.path.join(base_dir, "core", "samar-id", ".env.example")
if not os.path.exists(id_env) and os.path.exists(id_env_ex):
    shutil.copy(id_env_ex, id_env)
    print("[OK] Samar ID .env yaratildi.")

upload_cloud = os.path.join(base_dir, "core", "samar-cloud", "uploads")
os.makedirs(upload_cloud, exist_ok=True)

upload_avatars = os.path.join(base_dir, "core", "samar-id", "uploads", "avatars")
os.makedirs(upload_avatars, exist_ok=True)

print("[OK] Barcha papkalar tayyor.")

print("\n" + "=" * 60)
print("  SERVER TO'LIQ TAYYOR BO'LDI!")
print("  - Samar ID uchun:     'start_samar_id.bat' (Port 8000)")
print("  - Samar Cloud uchun:  'start_server.bat'   (Port 8001)")
print("=" * 60)
