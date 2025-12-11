# main.py
import os
import uuid
import datetime
import logging
from typing import Optional

from fastapi import FastAPI, HTTPException, Body, Request, status
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr, Field
from dotenv import load_dotenv
from pymongo import MongoClient, errors
from passlib.context import CryptContext
import jwt
from bson import ObjectId

# Load env
load_dotenv()

# -------- Configuration ----------
MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
MASTER_DB = os.getenv("MASTER_DB", "master_db")
JWT_SECRET = os.getenv("JWT_SECRET", "supersecret")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
JWT_EXPIRE_SECONDS = int(os.getenv("JWT_EXPIRE_SECONDS", "3600"))

# Logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("backend-wedding")

# Mongo client
try:
    client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
    client.server_info()  # quick check to raise early if unreachable
except Exception as e:
    logger.error("Cannot connect to MongoDB: %s", e)
    # We continue to start app; endpoints will return errors if DB unreachable.

master_db = client[MASTER_DB]
orgs_col = master_db["organizations"]

# Use bcrypt_sha256 to avoid bcrypt 72-byte truncation issues
pwd_context = CryptContext(schemes=["bcrypt_sha256"], deprecated="auto")

app = FastAPI(title="Org Backend - Wedding Project", version="1.0.0")

# CORS (adjust origins if required)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # For dev. In prod, restrict origins.
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------- Pydantic models ----------
class OrgCreateModel(BaseModel):
    organization_name: str = Field(..., min_length=2, max_length=100)
    email: EmailStr
    password: str = Field(..., min_length=6)


class AdminLoginModel(BaseModel):
    email: EmailStr
    password: str


class OrgUpdateModel(BaseModel):
    organization_name: str
    new_organization_name: Optional[str] = None
    new_email: Optional[EmailStr] = None
    new_password: Optional[str] = None


class OrgDeleteModel(BaseModel):
    organization_name: str
    admin_email: EmailStr


# ---------- Helpers ----------
def normalize_name(name: str) -> str:
    # produce a safe collection name. keep alnum + underscores
    s = "".join(c if (c.isalnum() or c == "_") else "_" for c in name.strip().lower())
    # collapse multiple underscores
    while "__" in s:
        s = s.replace("__", "_")
    return s[:80]  # limit length


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
    return token


def serialize_mongo(doc):
    new_doc = {}
    for k, v in doc.items():
        if isinstance(v, ObjectId):
            new_doc[k] = str(v)
        elif isinstance(v, datetime.datetime):
            new_doc[k] = v.isoformat()
        else:
            new_doc[k] = v
    return new_doc


# ---------- Global exception handler ----------
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.exception("Unhandled error for %s %s: %s", request.method, request.url, exc)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": f"Internal server error: {repr(exc)}"},
    )


# ---------- Routes ----------
@app.get("/health")
def health():
    """Simple health check for readiness / liveness."""
    try:
        client.admin.command("ping")
        return {"ok": True, "db": "reachable"}
    except Exception as e:
        logger.warning("Health check DB ping failed: %s", e)
        return JSONResponse(status_code=503, content={"ok": False, "db": "unreachable", "detail": str(e)})


@app.post("/org/create")
def create_org(data: OrgCreateModel = Body(...)):
    try:
        # uniqueness checks
        if orgs_col.find_one({"organization_name": data.organization_name}):
            raise HTTPException(status_code=400, detail="Organization with that name already exists")
        if orgs_col.find_one({"email": data.email}):
            raise HTTPException(status_code=400, detail="Admin email already used")

        collection_name = f"org_{normalize_name(data.organization_name)}"

        # create a new collection (this will create on first insert; we can create explicitly)
        if collection_name not in master_db.list_collection_names():
            master_db.create_collection(collection_name)

        hashed_pw = hash_password(data.password)
        org_id = str(uuid.uuid4())

        org_doc = {
            "org_id": org_id,
            "organization_name": data.organization_name,
            "email": data.email,
            "password_hash": hashed_pw,
            "collection_name": collection_name,
            "created_at": datetime.datetime.utcnow(),
        }

        orgs_col.insert_one(org_doc)

        logger.info("Created org %s with collection %s", data.organization_name, collection_name)
        return {"ok": True, "org_id": org_id, "collection_name": collection_name}
    except HTTPException:
        raise
    except errors.PyMongoError as e:
        logger.error("MongoDB error on create_org: %s", e)
        raise HTTPException(status_code=500, detail="Database error")
    except Exception as e:
        raise


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
    except Exception:
        raise


@app.get("/org/get")
def get_org(organization_name: str):
    try:
        org = orgs_col.find_one({"organization_name": organization_name}, {"password_hash": 0})
        if not org:
            raise HTTPException(status_code=404, detail="Organization not found")
        return {"ok": True, "organization": serialize_mongo(org)}
    except HTTPException:
        raise
    except Exception:
        raise


@app.put("/org/update")
def update_org(data: OrgUpdateModel = Body(...)):
    try:
        org = orgs_col.find_one({"organization_name": data.organization_name})
        if not org:
            raise HTTPException(status_code=404, detail="Organization not found")

        update_fields = {}
        if data.new_organization_name:
            # check uniqueness
            if orgs_col.find_one({"organization_name": data.new_organization_name}):
                raise HTTPException(status_code=400, detail="New organization name already exists")
            new_col = f"org_{normalize_name(data.new_organization_name)}"
            # create new collection and (optionally) move data - here we just create the collection
            if new_col not in master_db.list_collection_names():
                master_db.create_collection(new_col)
            update_fields["organization_name"] = data.new_organization_name
            update_fields["collection_name"] = new_col

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
    except Exception:
        raise


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
    except Exception:
        raise


@app.get("/")
def root():
    return {"ok": True, "msg": "Backend running. Use /docs for API docs."}

