# main.py
import os
import uuid
import datetime
import logging
from typing import Optional

from fastapi import FastAPI, HTTPException, Body
from pydantic import BaseModel, EmailStr, Field
from dotenv import load_dotenv
from pymongo import MongoClient, errors
from passlib.context import CryptContext
import jwt

# load .env
load_dotenv()

# ---------- Config ----------
MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
MASTER_DB = os.getenv("MASTER_DB", "master_db")
JWT_SECRET = os.getenv("JWT_SECRET", "supersecret")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
JWT_EXPIRE_SECONDS = int(os.getenv("JWT_EXPIRE_SECONDS", "3600"))

# ---------- Logging ----------
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("backend-wedding")

# ---------- Mongo client (created on startup) ----------
client: Optional[MongoClient] = None
master_db = None
orgs_col = None

# Use bcrypt_sha256 to avoid bcrypt 72-byte limit
pwd_context = CryptContext(schemes=["bcrypt_sha256"], deprecated="auto")

app = FastAPI(title="Org Backend")


# ---------- Pydantic models ----------
class OrgCreateModel(BaseModel):
    organization_name: str = Field(..., min_length=3, max_length=50, pattern=r"^[A-Za-z0-9 _-]+$")
    email: EmailStr
    password: str = Field(..., min_length=8)


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


def normalize_name(name: str) -> str:
    return "".join(c for c in name.lower() if c.isalnum() or c == "_").replace(" ", "_")


from bson import ObjectId


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


# ---------- Startup & Shutdown ----------
@app.on_event("startup")
def on_startup():
    global client, master_db, orgs_col
    try:
        logger.info("Trying to connect to MongoDB: %s", MONGO_URI)
        # short timeout so startup fails fast if Mongo is unreachable
        client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000, tls=True)
        # verify connection
        info = client.server_info()
        logger.info("Connected to MongoDB, version=%s", info.get("version"))
        master_db = client[MASTER_DB]
        orgs_col = master_db["organizations"]
        app.state.mongo_ok = True
    except Exception as e:
        logger.exception("MongoDB connection failed on startup: %s", e)
        app.state.mongo_ok = False


@app.on_event("shutdown")
def on_shutdown():
    global client
    try:
        if client:
            client.close()
            logger.info("Closed MongoDB connection")
    except Exception:
        logger.exception("Error closing MongoDB connection")


# ---------- Routes ----------
@app.get("/health")
def health():
    """
    Health endpoint: returns app + db status and some diagnostics.
    """
    db_status = getattr(app.state, "mongo_ok", False)
    return {
        "ok": db_status,
        "app": "ok",
        "mongo_connected": db_status,
        "master_db": MASTER_DB,
    }


@app.post("/org/create")
def create_org(data: OrgCreateModel = Body(...)):
    try:
        if not getattr(app.state, "mongo_ok", False):
            raise HTTPException(status_code=503, detail="MongoDB not connected")

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
        logger.exception("Error in create_org: %s", e)
        raise HTTPException(status_code=500, detail=f"Internal server error: {repr(e)}")


@app.post("/admin/login")
def admin_login(data: AdminLoginModel = Body(...)):
    try:
        if not getattr(app.state, "mongo_ok", False):
            raise HTTPException(status_code=503, detail="MongoDB not connected")

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
        logger.exception("Error in admin_login: %s", e)
        raise HTTPException(status_code=500, detail=f"Internal server error: {repr(e)}")


@app.get("/org/get")
def get_org(organization_name: str):
    try:
        if not getattr(app.state, "mongo_ok", False):
            raise HTTPException(status_code=503, detail="MongoDB not connected")

        org = orgs_col.find_one({"organization_name": organization_name}, {"password_hash": 0})
        if not org:
            raise HTTPException(status_code=404, detail="Organization not found")

        org = serialize_mongo(org)
        return {"ok": True, "organization": org}

    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Error in get_org: %s", e)
        raise HTTPException(status_code=500, detail=f"Internal server error: {repr(e)}")


@app.put("/org/update")
def update_org(data: OrgUpdateModel = Body(...)):
    try:
        if not getattr(app.state, "mongo_ok", False):
            raise HTTPException(status_code=503, detail="MongoDB not connected")

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
        logger.exception("Error in update_org: %s", e)
        raise HTTPException(status_code=500, detail=f"Internal server error: {repr(e)}")


@app.delete("/org/delete")
def delete_org(data: OrgDeleteModel = Body(...)):
    try:
        if not getattr(app.state, "mongo_ok", False):
            raise HTTPException(status_code=503, detail="MongoDB not connected")

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
        logger.exception("Error in delete_org: %s", e)
        raise HTTPException(status_code=500, detail=f"Internal server error: {repr(e)}")


@app.get("/")
def root():
    return {"ok": True, "msg": "Backend running. Use /docs for API docs."}
