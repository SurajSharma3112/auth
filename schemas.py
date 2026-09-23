from pydantic import BaseModel, EmailStr
from datetime import datetime


# What the client sends when signing up
class UserCreate(BaseModel):
    email: EmailStr
    password: str


# What we send back after signup/lookup — notice: no password field at all
class UserOut(BaseModel):
    id: int
    email: EmailStr
    created_at: datetime

    class Config:
        from_attributes = True


# What we send back after a successful login
class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
