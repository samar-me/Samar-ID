from pydantic import BaseModel, EmailStr, Field
from typing import Optional, List

class UserRegister(BaseModel):
    samar_id: str = Field(..., min_length=3, max_length=32, description="Masalan: azizbek yoki shoxrux")
    full_name: str = Field(..., min_length=2, max_length=100)
    email: Optional[EmailStr] = None
    password: str = Field(..., min_length=6, description="Xavfsiz parol")

class UserLogin(BaseModel):
    samar_id_or_email: str
    password: str

class ProfileUpdate(BaseModel):
    full_name: Optional[str] = Field(None, min_length=2, max_length=100)
    phone: Optional[str] = None
    bio: Optional[str] = None
    specialty: Optional[str] = None

class PasswordChange(BaseModel):
    old_password: str
    new_password: str = Field(..., min_length=6)

class PinSet(BaseModel):
    pin_code: str = Field(..., min_length=4, max_length=6)

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
    role: str
    two_factor_enabled: bool = False
    created_at: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserResponse
