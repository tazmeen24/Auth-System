from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from datetime import timedelta
from typing import Optional

from database import get_db_connection
from auth_utils import (
    verify_password, 
    get_password_hash, 
    create_access_token, 
    decode_access_token,
    ACCESS_TOKEN_EXPIRE_MINUTES
)
from models import UserCreate, UserLogin, UserResponse, Token

app = FastAPI(title="Auth System API")

# Configure CORS for React frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:5173"],  # React dev servers
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security scheme
security = HTTPBearer()

# Dependency to get current user from token
async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> dict:
    """Validate token and return current user"""
    token = credentials.credentials
    payload = decode_access_token(token)
    
    if payload is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    username: str = payload.get("sub")
    if username is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
        )
    
    # Get user from database
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
        user = cursor.fetchone()
        
        if user is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found",
            )
        
        return dict(user)

@app.get("/")
def root():
    """Root endpoint"""
    return {"message": "Auth System API"}

@app.post("/auth/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def register(user: UserCreate):
    """Register a new user"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        
        # Check if user already exists
        cursor.execute("SELECT * FROM users WHERE email = %s OR username = %s", 
                      (user.email, user.username))
        existing_user = cursor.fetchone()
        
        if existing_user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email or username already registered"
            )
        
        # Hash password and create user
        hashed_password = get_password_hash(user.password)
        
        cursor.execute(
            """
            INSERT INTO users (email, username, hashed_password)
            VALUES (%s, %s, %s)
            RETURNING id, email, username, is_active, created_at
            """,
            (user.email, user.username, hashed_password)
        )
        
        new_user = cursor.fetchone()
        return dict(new_user)

@app.post("/auth/login", response_model=Token)
def login(user: UserLogin):
    """Login and get access token"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        
        # Get user from database
        cursor.execute("SELECT * FROM users WHERE username = %s", (user.username,))
        db_user = cursor.fetchone()
        
        if not db_user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect username or password",
            )
        
        # Verify password
        if not verify_password(user.password, db_user["hashed_password"]):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect username or password",
            )
        
        # Check if user is active
        if not db_user["is_active"]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Inactive user account"
            )
        
        # Create access token
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": db_user["username"]},
            expires_delta=access_token_expires
        )
        
        return {"access_token": access_token, "token_type": "bearer"}

@app.get("/auth/me", response_model=UserResponse)
async def get_current_user_info(current_user: dict = Depends(get_current_user)):
    """Get current user information"""
    return UserResponse(
        id=current_user["id"],
        email=current_user["email"],
        username=current_user["username"],
        is_active=current_user["is_active"],
        created_at=current_user["created_at"]
    )

@app.get("/protected")
async def protected_route(current_user: dict = Depends(get_current_user)):
    """Example protected route"""
    return {
        "message": f"Hello {current_user['username']}, this is a protected route!",
        "user_id": current_user["id"]
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)