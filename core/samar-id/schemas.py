from pydantic import BaseModel, EmailStr, Field
from typing import Optional, List

class UserRegister(BaseModel):
    samar_id: str = Field(..., min_length=3, max_length=32)
    full_name: str = Field(..., min_length=2, max_length=100)
    email: Optional[EmailStr] = None
    password: str = Field(..., min_length=6)
    captcha_answer: Optional[str] = None

class UserLogin(BaseModel):
    samar_id_or_email: Optional[str] = None
    samar_id: Optional[str] = None
    password: str
    captcha_answer: Optional[str] = None

class ProfileUpdate(BaseModel):
    full_name: Optional[str] = Field(None, min_length=2, max_length=100)
    phone: Optional[str] = None
    bio: Optional[str] = None
    specialty: Optional[str] = None

class PasswordChange(BaseModel):
    old_password: str
    new_password: str = Field(..., min_length=6)

class GuardianSet(BaseModel):
    guardian_samar_id: Optional[str] = None
    guardian_id: Optional[str] = None

class GuardianRequestOtp(BaseModel):
    samar_id: str

class GuardianVerifyOtp(BaseModel):
    samar_id: str
    otp_code: Optional[str] = None
    otp: Optional[str] = None

class PhoneSendCode(BaseModel):
    phone: str

class PhoneVerifyCode(BaseModel):
    phone: Optional[str] = None
    code: str

class NotificationItem(BaseModel):
    id: int
    from_user: str
    title: str
    message: str
    type: str
    is_read: bool
    action_data: Optional[str] = ""
    created_at: Optional[str] = ""

class SessionItem(BaseModel):
    id: int
    device_name: str
    ip_address: Optional[str]
    last_active: str
    is_current: bool = False

class UserResponse(BaseModel):
    id: int
    samar_id: str
    full_name: str
    email: Optional[str] = None
    phone: Optional[str] = None
    phone_verified: bool = False
    bio: Optional[str] = None
    specialty: Optional[str] = None
    avatar_path: Optional[str] = None
    guardian_id: Optional[str] = None
    security_freeze_until: Optional[str] = None
    role: str
    two_factor_enabled: bool = False
    created_at: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: Optional[UserResponse] = None

class RecoveryLogin(BaseModel):
    samar_id: str
    code: Optional[str] = None
    recovery_code: Optional[str] = None

class RecoveryCodesResponse(BaseModel):
    codes: List[str]

class ConnectedAppItem(BaseModel):
    id: int
    client_id: str
    app_name: str
    app_icon: str
    scopes: str
    connected_at: str

class PasskeyRegisterRequest(BaseModel):
    credential_id: str
    public_key: Optional[str] = ""
    device_name: Optional[str] = "Face ID / Touch ID"

class PasskeyLoginRequest(BaseModel):
    samar_id: str
    credential_id: Optional[str] = ""

class OAuthApproveRequest(BaseModel):
    client_id: str
    app_name: Optional[str] = "Samar App"
    app_icon: Optional[str] = "📱"
    redirect_uri: str
    scopes: Optional[str] = "profile,email"
    state: Optional[str] = ""

class OAuthTokenRequest(BaseModel):
    code: str
    client_id: Optional[str] = None
    redirect_uri: Optional[str] = None
    grant_type: Optional[str] = "authorization_code"

class OAuthTokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int = 2592000
    scope: str = "profile,email"

