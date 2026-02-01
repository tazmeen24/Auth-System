from pydantic import BaseModel, EmailStr
from typing import Optional
from datetime import datetime

class UserCreate(BaseModel):
    """Schema for creating a new user"""
    email: EmailStr
    username: str
    password: str

class UserLogin(BaseModel):
    """Schema for user login"""
    username: str
    password: str

class UserResponse(BaseModel):
    """Schema for user response (no password)"""
    id: int
    email: str
    username: str
    is_active: bool
    created_at: datetime

class Token(BaseModel):
    """Schema for token response"""
    access_token: str
    token_type: str

class TokenData(BaseModel):
    """Schema for token payload data"""
    username: Optional[str] = None