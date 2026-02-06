from fastapi import FastAPI, APIRouter, HTTPException, Request, Header
from fastapi.responses import JSONResponse
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
from jose import jwt, JWTError
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr, ConfigDict
from typing import Optional, Dict, List
from pathlib import Path
from datetime import datetime, timedelta, timezone
import os
import uuid
import logging
import asyncio
import resend

# ─────────────────────────────────────────────
# ENV + APP SETUP
# ─────────────────────────────────────────────

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / ".env")

app = FastAPI()
api_router = APIRouter(prefix="/api")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# MongoDB
mongo_url = os.environ["MONGO_URL"]
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ["DB_NAME"]]

# Email
resend.api_key = os.environ.get("RESEND_API_KEY")
SENDER_EMAIL = os.environ.get("RESEND_SENDER_EMAIL", "onboarding@resend.dev")

# JWT
JWT_SECRET = os.environ.get("JWT_SECRET", "dev-secret-change-this")
JWT_ALGORITHM = "HS256"
JWT_EXPIRE_DAYS = 7

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# ─────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(password: str, hashed: str) -> bool:
    return pwd_context.verify(password, hashed)

def create_access_token(user_id: str) -> str:
    payload = {
        "sub": user_id,
        "exp": datetime.utcnow() + timedelta(days=JWT_EXPIRE_DAYS)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def decode_access_token(token: str) -> Optional[str]:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload.get("sub")
    except JWTError:
        return None

async def get_current_user(authorization: Optional[str] = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Not authenticated")

    token = authorization.replace("Bearer ", "")
    user_id = decode_access_token(token)

    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid token")

    user = await db.users.find_one({"user_id": user_id}, {"_id": 0})
    if not user:
        raise HTTPException(status_code=401, detail="User not found")

    if isinstance(user["created_at"], str):
        user["created_at"] = datetime.fromisoformat(user["created_at"])

    return user

# ─────────────────────────────────────────────
# MODELS
# ─────────────────────────────────────────────

class User(BaseModel):
    model_config = ConfigDict(extra="ignore")
    user_id: str
    email: EmailStr
    name: str
    subscription_tier: str
    created_at: datetime

class Subscription(BaseModel):
    model_config = ConfigDict(extra="ignore")
    subscription_id: str
    user_id: str
    company: str
    amount: float
    renewal_date: datetime
    status: str
    created_at: datetime

class SubscriptionCreate(BaseModel):
    company: str
    amount: float
    renewal_date: str

# ─────────────────────────────────────────────
# ROUTES
# ─────────────────────────────────────────────

@api_router.get("/")
async def root():
    return {"message": "CancelShield API", "version": "1.0.0"}

# AUTH

@api_router.post("/auth/register")
async def register(request: Request):
    body = await request.json()
    email = body.get("email")
    password = body.get("password")
    name = body.get("name", "")

    if not email or not password:
        raise HTTPException(status_code=400, detail="Email and password required")

    if await db.users.find_one({"email": email}):
        raise HTTPException(status_code=400, detail="Email already exists")

    user_id = f"user_{uuid.uuid4().hex[:12]}"
    user = {
        "user_id": user_id,
        "email": email,
        "name": name,
        "password_hash": hash_password(password),
        "subscription_tier": "free",
        "created_at": datetime.now(timezone.utc).isoformat()
    }

    await db.users.insert_one(user)
    return {"access_token": create_access_token(user_id)}

@api_router.post("/auth/login")
async def login(request: Request):
    body = await request.json()
    email = body.get("email")
    password = body.get("password")

    user = await db.users.find_one({"email": email})
    if not user or not verify_password(password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    return {"access_token": create_access_token(user["user_id"])}

# SUBSCRIPTIONS

@api_router.get("/subscriptions")
async def list_subscriptions(user=Header(None), authorization: str = Header(...)):
    user = await get_current_user(authorization)
    subs = await db.subscriptions.find(
        {"user_id": user["user_id"]}, {"_id": 0}
    ).to_list(100)

    for s in subs:
        s["renewal_date"] = datetime.fromisoformat(s["renewal_date"])
        s["created_at"] = datetime.fromisoformat(s["created_at"])

    return subs

@api_router.post("/subscriptions")
async def create_subscription(data: SubscriptionCreate, authorization: str = Header(...)):
    user = await get_current_user(authorization)

    sub = {
        "subscription_id": f"sub_{uuid.uuid4().hex[:12]}",
        "user_id": user["user_id"],
        "company": data.company,
        "amount": data.amount,
        "renewal_date": data.renewal_date,
        "status": "active",
        "created_at": datetime.now(timezone.utc).isoformat()
    }

    await db.subscriptions.insert_one(sub)
    return {"success": True}

# EMAIL TEST

@api_router.post("/alerts/test")
async def send_test_email(authorization: str = Header(...)):
    user = await get_current_user(authorization)

    html = f"""
    <h2>CancelShield Alert</h2>
    <p>This is a test reminder email.</p>
    """

    await asyncio.to_thread(
        resend.Emails.send,
        {
            "from": SENDER_EMAIL,
            "to": [user["email"]],
            "subject": "CancelShield Test Alert",
            "html": html
        }
    )

    return {"success": True}

# ─────────────────────────────────────────────
# FINALIZE
# ─────────────────────────────────────────────

app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("shutdown")
async def shutdown():
    client.close()
