import os
import io
import json
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from googleapiclient.http import MediaIoBaseUpload, MediaIoBaseDownload
from dotenv import load_dotenv

load_dotenv()

SCOPES = [
    'https://www.googleapis.com/auth/drive',
    'https://www.googleapis.com/auth/drive.file'
]

CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "")
CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "")
TOKEN_FILE = os.path.join(os.path.dirname(__file__), "token.json")
LOCAL_UPLOAD_DIR = os.path.join(os.path.dirname(__file__), "uploads")
os.makedirs(LOCAL_UPLOAD_DIR, exist_ok=True)

class GoogleDriveManager:
    def __init__(self):
        self.creds = None
        self.service = None
        self.root_folder_id = None
        self._load_credentials()

    def _load_credentials(self):
        """Loads cached credentials from token.json or database if present."""
        if os.path.exists(TOKEN_FILE):
            try:
                self.creds = Credentials.from_authorized_user_file(TOKEN_FILE, SCOPES)
            except Exception as e:
                print(f"[Drive] Warning loading token.json: {e}")
                self.creds = None

        if self.creds and self.creds.expired and self.creds.refresh_token:
            try:
                self.creds.refresh(Request())
                with open(TOKEN_FILE, 'w') as f:
                    f.write(self.creds.to_json())
                print("[Drive] Credentials refreshed successfully.")
            except Exception as e:
                print(f"[Drive] Failed to refresh token: {e}")
                self.creds = None

        if self.creds and self.creds.valid:
            try:
                self.service = build('drive', 'v3', credentials=self.creds)
                self._ensure_root_folder()
            except Exception as e:
                print(f"[Drive] Service build error: {e}")
                self.service = None

    def is_connected(self) -> bool:
        return bool(self.service is not None)

    def get_auth_url(self, redirect_uri: str) -> str:
        """Generates Google OAuth 2.0 authorization URL."""
        client_config = {
            "web": {
                "client_id": CLIENT_ID,
                "client_secret": CLIENT_SECRET,
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
                "redirect_uris": [redirect_uri]
            }
        }
        flow = Flow.from_client_config(
            client_config,
            scopes=SCOPES,
            redirect_uri=redirect_uri
        )
        auth_url, _ = flow.authorization_url(
            access_type='offline',
            include_granted_scopes='true',
            prompt='consent'
        )
        return auth_url

    def complete_auth(self, code: str, redirect_uri: str) -> bool:
        """Exchanges auth code for tokens and saves to token.json."""
        client_config = {
            "web": {
                "client_id": CLIENT_ID,
                "client_secret": CLIENT_SECRET,
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
                "redirect_uris": [redirect_uri]
            }
        }
        flow = Flow.from_client_config(
            client_config,
            scopes=SCOPES,
            redirect_uri=redirect_uri
        )
        flow.fetch_token(code=code)
        self.creds = flow.credentials
        with open(TOKEN_FILE, 'w') as f:
            f.write(self.creds.to_json())

        self.service = build('drive', 'v3', credentials=self.creds)
        self._ensure_root_folder()
        return True

    def _ensure_root_folder(self):
        """Ensures 'Samar OS Cloud Vault' root directory exists in Google Drive."""
        if not self.service:
            return
        try:
            query = "name = 'Samar OS Cloud Vault' and mimeType = 'application/vnd.google-apps.folder' and trashed = false"
            results = self.service.files().list(q=query, spaces='drive', fields='files(id, name)').execute()
            files = results.get('files', [])
            if files:
                self.root_folder_id = files[0]['id']
            else:
                folder_metadata = {
                    'name': 'Samar OS Cloud Vault',
                    'mimeType': 'application/vnd.google-apps.folder',
                    'description': 'Samar OS Mega-Ecosystem Sovereign Storage'
                }
                folder = self.service.files().create(body=folder_metadata, fields='id').execute()
                self.root_folder_id = folder.get('id')
        except Exception as e:
            print(f"[Drive] Root folder creation warning: {e}")

    def get_storage_quota(self) -> dict:
        """Returns storage quota details (total, used, percentage, user email)."""
        if not self.service:
            return {
                "connected": False,
                "total_bytes": 5 * 1024 * 1024 * 1024 * 1024, # 5 TB default preview
                "used_bytes": 0,
                "free_bytes": 5 * 1024 * 1024 * 1024 * 1024,
                "used_formatted": "0 B",
                "total_formatted": "5.0 TB",
                "percent_used": 0.0,
                "account_email": None
            }

        try:
            about = self.service.about().get(fields="storageQuota, user").execute()
            quota = about.get('storageQuota', {})
            user = about.get('user', {})

            limit = int(quota.get('limit', 0))
            usage = int(quota.get('usage', 0))
            if limit == 0:
                limit = 5 * 1024 * 1024 * 1024 * 1024 # 5 TB fallback

            free = max(0, limit - usage)
            percent = round((usage / limit) * 100, 2) if limit > 0 else 0.0

            def fmt(b):
                if b >= 1024**4: return f"{b / (1024**4):.1f} TB"
                if b >= 1024**3: return f"{b / (1024**3):.1f} GB"
                if b >= 1024**2: return f"{b / (1024**2):.1f} MB"
                return f"{b / 1024:.1f} KB"

            return {
                "connected": True,
                "total_bytes": limit,
                "used_bytes": usage,
                "free_bytes": free,
                "used_formatted": fmt(usage),
                "total_formatted": fmt(limit),
                "percent_used": percent,
                "account_email": user.get('emailAddress')
            }
        except Exception as e:
            print(f"[Drive] Error fetching quota: {e}")
            return {
                "connected": False,
                "error": str(e),
                "total_bytes": 5 * 1024 * 1024 * 1024 * 1024,
                "used_bytes": 0,
                "used_formatted": "0 B",
                "total_formatted": "5.0 TB",
                "percent_used": 0.0,
                "account_email": None
            }

    def upload_file(self, file_content: bytes, filename: str, mime_type: str) -> dict:
        """Uploads file to Google Drive or local fallback."""
        if not self.service:
            # Fallback to local storage
            local_path = os.path.join(LOCAL_UPLOAD_DIR, filename)
            with open(local_path, "wb") as f:
                f.write(file_content)
            return {
                "drive_file_id": None,
                "storage_path": local_path,
                "web_view_link": None,
                "thumbnail_link": None
            }

        try:
            file_metadata = {
                'name': filename,
                'parents': [self.root_folder_id] if self.root_folder_id else []
            }
            media = MediaIoBaseUpload(
                io.BytesIO(file_content),
                mimetype=mime_type or 'application/octet-stream',
                resumable=True
            )
            file = self.service.files().create(
                body=file_metadata,
                media_body=media,
                fields='id, name, webViewLink, webContentLink, thumbnailLink'
            ).execute()

            return {
                "drive_file_id": file.get('id'),
                "storage_path": None,
                "web_view_link": file.get('webViewLink'),
                "thumbnail_link": file.get('thumbnailLink')
            }
        except Exception as e:
            print(f"[Drive] Upload error, falling back to local: {e}")
            local_path = os.path.join(LOCAL_UPLOAD_DIR, filename)
            with open(local_path, "wb") as f:
                f.write(file_content)
            return {
                "drive_file_id": None,
                "storage_path": local_path,
                "web_view_link": None,
                "thumbnail_link": None
            }

    def download_file(self, drive_file_id: str) -> bytes:
        """Downloads file bytes from Google Drive."""
        if not self.service:
            raise Exception("Google Drive xizmati ulanmagan")

        request = self.service.files().get_media(fileId=drive_file_id)
        fh = io.BytesIO()
        downloader = MediaIoBaseDownload(fh, request)
        done = False
        while not done:
            status, done = downloader.next_chunk()
        fh.seek(0)
        return fh.read()

    def delete_file(self, drive_file_id: str):
        """Moves file to Google Drive trash."""
        if not self.service or not drive_file_id:
            return
        try:
            self.service.files().update(fileId=drive_file_id, body={'trashed': True}).execute()
        except Exception as e:
            print(f"[Drive] Delete error: {e}")

drive_manager = GoogleDriveManager()
