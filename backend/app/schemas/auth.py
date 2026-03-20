from pydantic import BaseModel, EmailStr


class UserCreate(BaseModel):
    email: EmailStr
    password: str


class UserLogin(BaseModel):
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class MeResponse(BaseModel):
    id: int
    email: EmailStr
    is_admin: bool
    group_ids: list[int]


class PasswordChangePayload(BaseModel):
    current_password: str
    new_password: str


class AdminUserCreate(BaseModel):
    email: EmailStr
    password: str
    is_admin: bool = False
    group_ids: list[int] = []


class AdminResetPasswordPayload(BaseModel):
    new_password: str
