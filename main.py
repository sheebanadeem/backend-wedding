# main.py
import os
import uuid
import datetime
import logging
from typing import Optional, Dict, Any

from fastapi import FastAPI, HTTPException, Body, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr, Field
from dotenv import load_dotenv
from pymongo import MongoClient, ASCENDING
from passlib.context import CryptContext
import jwt
from bson import ObjectId

# load env
load_dotenv()

# logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("backend-wedding")

# config
MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
MASTER_DB = os.getenv("MASTER_DB", "master_db")
JWT_SECRET = os.getenv("JWT_SECRET", "supersecret")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
JWT_EXPIRE_SECONDS = int(os.getenv("JWT_EXPIRE_SECONDS", "3600"))

# client (simple synchronous client)
client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
master_db = client[MASTER_DB]
orgs_col = master_db["organizations"]

# ensure useful indexes
try:
    orgs_col.create_index([("organization_name", ASCENDING)], unique=True)
    orgs_col.create_index([("email", ASCENDING)], unique=True)
except Exception as e:
    logger.warning("Could not ensure indexes: %s", e)

# password hashing: bcrypt_sha256 avoids the 72-byte bcrypt limit
pwd_context = CryptContext(schemes=["bcrypt_sha256"], deprecated="auto")

app = FastAPI(title="Org Backend — Wedding Project")

# CORS — adjust origin list in production
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # tighten for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------- Pydantic models ----------------
class OrgCreateModel(BaseModel):
    organization_name: str = Field(..., min_length=3, max_length=50, pattern=r"^[A-Za-z0-9 _-]+$")
    email: EmailStr
    password: str = Field(..., min_length=8)


class AdminLoginModel(BaseModel):
    email: EmailStr
    password: str


class OrgUpdateModel(BaseModel):
    organization_name: str
    new_organization_name: Optional[str] = Field(None, min_length=3, max_length=50, pattern=r"^[A-Za-z0-9 _-]+$")
    new_email: Optional[EmailStr] = None
    new_password: Optional[str] = Field(None, min_length=8)


class OrgDeleteModel(BaseModel):
    organization_name: str
    admin_email: EmailStr


# ---------------- helpers ----------------
def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        return pwd_context.verify(plain_password, hashed_password)
    except Exception:
        return False


def create_jwt(payload: dict, expires_in: int = JWT_EXPIRE_SECONDS) -> str:
    to_encode = payload.copy()
    expire = datetime.datetime.utcnow() + datetime.timedelta(seconds=expires_in)
    to_encode.update({"exp": expire})
    token = jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALGORITHM)
    # jwt.encode returns bytes in some PyJWT versions — ensure string
    if isinstance(token, bytes):
        token = token.decode("utf-8")
    return token


def normalize_name(name: str) -> str:
    return "".join(c for c in name.lower() if c.isalnum() or c == "_").replace(" ", "_")


def serialize_mongo(doc: Dict[str, Any]) -> Dict[str, Any]:
    new_doc: Dict[str, Any] = {}
    for k, v in doc.items():
        if isinstance(v, ObjectId):
            new_doc[k] = str(v)
        elif isinstance(v, datetime.datetime):
            new_doc[k] = v.isoformat()
        else:
            new_doc[k] = v
    return new_doc


# ---------------- routes ----------------
@app.post("/org/create")
def create_org(data: OrgCreateModel = Body(...)):
    try:
        if orgs_col.find_one({"organization_name": data.organization_name}):
            raise HTTPException(status_code=400, detail="Organization with that name already exists")
        if orgs_col.find_one({"email": data.email}):
            raise HTTPException(status_code=400, detail="Admin email already used")

        hashed_pw = hash_password(data.password)
        org_id = str(uuid.uuid4())
        collection_name = f"org_{normalize_name(data.organization_name)}"

        org_doc = {
            "org_id": org_id,
            "organization_name": data.organization_name,
            "email": data.email,
            "password_hash": hashed_pw,
            "collection_name": collection_name,
            "created_at": datetime.datetime.utcnow(),
        }

        orgs_col.insert_one(org_doc)
        return {"ok": True, "org_id": org_id, "collection_name": collection_name}
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("create_org error")
        raise HTTPException(status_code=500, detail=f"Internal server error: {repr(e)}")


@app.post("/admin/login")
def admin_login(data: AdminLoginModel = Body(...)):
    try:
        admin = orgs_col.find_one({"email": data.email})
        if not admin:
            raise HTTPException(status_code=401, detail="Invalid credentials")

        if not verify_password(data.password, admin.get("password_hash", "")):
            raise HTTPException(status_code=401, detail="Invalid credentials")

        payload = {"email": admin["email"], "org_id": admin["org_id"], "organization_name": admin["organization_name"]}
        token = create_jwt(payload)
        return {"ok": True, "token": token}
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("admin_login error")
        raise HTTPException(status_code=500, detail=f"Internal server error: {repr(e)}")


@app.get("/org/get")
def get_org(organization_name: str):
    try:
        org = orgs_col.find_one({"organization_name": organization_name}, {"password_hash": 0})
        if not org:
            raise HTTPException(status_code=404, detail="Organization not found")
        return {"ok": True, "organization": serialize_mongo(org)}
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("get_org error")
        raise HTTPException(status_code=500, detail=f"Internal server error: {repr(e)}")


@app.put("/org/update")
def update_org(data: OrgUpdateModel = Body(...)):
    try:
        org = orgs_col.find_one({"organization_name": data.organization_name})
        if not org:
            raise HTTPException(status_code=404, detail="Organization not found")

        update_fields = {}
        if data.new_organization_name:
            update_fields["organization_name"] = data.new_organization_name
            update_fields["collection_name"] = f"org_{normalize_name(data.new_organization_name)}"
        if data.new_email:
            if orgs_col.find_one({"email": data.new_email, "organization_name": {"$ne": data.organization_name}}):
                raise HTTPException(status_code=400, detail="Email already in use")
            update_fields["email"] = data.new_email
        if data.new_password:
            update_fields["password_hash"] = hash_password(data.new_password)

        if not update_fields:
            raise HTTPException(status_code=400, detail="No update fields provided")

        orgs_col.update_one({"organization_name": data.organization_name}, {"$set": update_fields})
        return {"ok": True, "updated": update_fields}
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("update_org error")
        raise HTTPException(status_code=500, detail=f"Internal server error: {repr(e)}")


@app.delete("/org/delete")
def delete_org(data: OrgDeleteModel = Body(...)):
    try:
        org = orgs_col.find_one({"organization_name": data.organization_name})
        if not org:
            raise HTTPException(status_code=404, detail="Organization not found")

        if org.get("email") != data.admin_email:
            raise HTTPException(status_code=401, detail="Only the registered admin can delete the organization")

        col_name = org.get("collection_name")
        if col_name in master_db.list_collection_names():
            master_db.drop_collection(col_name)

        orgs_col.delete_one({"organization_name": data.organization_name})
        return {"ok": True, "deleted": data.organization_name}
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("delete_org error")
        raise HTTPException(status_code=500, detail=f"Internal server error: {repr(e)}")


@app.get("/")
def root():
    return {"ok": True, "msg": "Backend running. Use /docs for API docs."}
