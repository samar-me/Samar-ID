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
    print("\n[1/3] Virtual muhit (.venv) yaratilmoqda...")
    subprocess.check_call([sys.executable, "-m", "venv", venv_dir])
    print("[OK] Virtual muhit yaratildi.")
else:
    print("\n[1/3] Virtual muhit (.venv) allaqachon mavjud.")

# 2. Requirements
req_path = os.path.join(base_dir, "core", "samar-cloud", "requirements.txt")
print("\n[2/3] Samar Cloud kutubxonalari o'rnatilmoqda (1-2 daqiqa)...")
subprocess.check_call([venv_python, "-m", "pip", "install", "--upgrade", "pip"])
subprocess.check_call([venv_python, "-m", "pip", "install", "-r", req_path])
print("[OK] Kutubxonalar o'rnatildi.")

# 3. Environment & folders
print("\n[3/3] Sozlamalar tekshirilmoqda...")
cloud_env = os.path.join(base_dir, "core", "samar-cloud", ".env")
cloud_env_ex = os.path.join(base_dir, "core", "samar-cloud", ".env.example")
if not os.path.exists(cloud_env) and os.path.exists(cloud_env_ex):
    shutil.copy(cloud_env_ex, cloud_env)
    print("[OK] Samar Cloud .env yaratildi.")

upload_dir = os.path.join(base_dir, "core", "samar-cloud", "uploads")
os.makedirs(upload_dir, exist_ok=True)
print("[OK] Uploads papkasi tayyor.")

print("\n" + "=" * 60)
print("  SERVER MUAFFAQIYATLI O'RNATILDI!")
print("  Endi 'start_server.bat' faylini ishga tushiring.")
print("=" * 60)
