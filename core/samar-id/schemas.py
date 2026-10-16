from pydantic import BaseModel, EmailStr, Field
from typing import Optional, List

class UserRegister(BaseModel):
    samar_id: str = Field(..., min_length=3, max_length=32)
    full_name: str = Field(..., min_length=2, max_length=100)
    email: Optional[EmailStr] = None
    password: str = Field(..., min_length=6)
    captcha_answer: Optional[str] = None

class UserLogin(BaseModel):
    samar_id_or_email: str
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
    guardian_samar_id: str

class GuardianRequestOtp(BaseModel):
    samar_id: str

class GuardianVerifyOtp(BaseModel):
    samar_id: str
    otp_code: str

class NotificationItem(BaseModel):
    id: int
    from_user: str
    title: str
    message: str
    type: str
    is_read: bool
    action_data: Optional[str] = ""
    created_at: str

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
    user: UserResponse
