import os
import secrets
from datetime import datetime, timedelta
from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import APIKeyHeader
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, String, DateTime, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from dotenv import load_dotenv

load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY", "votre-clé-secrète-très-longue-et-aléatoire")
API_KEY = os.getenv("API_KEY", "votre-clé-api-pour-le-logiciel-client")

# Base de données SQLite
SQLALCHEMY_DATABASE_URL = "sqlite:///./licenses.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Modèle de licence
class License(Base):
    __tablename__ = "licenses"

    machine_id = Column(String, primary_key=True, index=True)
    license_key = Column(String, unique=True, index=True)
    expires_at = Column(DateTime)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)

Base.metadata.create_all(bind=engine)

app = FastAPI(title="License API")

# Sécurité : clé API pour les requêtes du logiciel
api_key_header = APIKeyHeader(name="X-API-Key")

def verify_api_key(api_key: str = Depends(api_key_header)):
    if api_key != API_KEY:
        raise HTTPException(status_code=403, detail="Invalid API Key")
    return api_key

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Schémas Pydantic
class LicenseRequest(BaseModel):
    machine_id: str

class LicenseResponse(BaseModel):
    license_key: str
    expires_at: datetime
    is_valid: bool

class VerificationRequest(BaseModel):
    machine_id: str
    license_key: str

class VerificationResponse(BaseModel):
    is_valid: bool
    message: str

# --- Endpoints ---
@app.post("/api/activate", response_model=LicenseResponse)
def activate_license(request: LicenseRequest, db: Session = Depends(get_db), api_key: str = Depends(verify_api_key)):
    # Vérifier si une licence existe déjà
    existing = db.query(License).filter(License.machine_id == request.machine_id).first()
    if existing:
        return LicenseResponse(
            license_key=existing.license_key,
            expires_at=existing.expires_at,
            is_valid=existing.is_active and existing.expires_at > datetime.utcnow()
        )

    # Créer une nouvelle licence
    license_key = secrets.token_hex(16)  # Génère une clé unique
    expires_at = datetime.utcnow() + timedelta(days=365)  # Valable 1 an

    new_license = License(
        machine_id=request.machine_id,
        license_key=license_key,
        expires_at=expires_at
    )
    db.add(new_license)
    db.commit()
    db.refresh(new_license)

    return LicenseResponse(
        license_key=license_key,
        expires_at=expires_at,
        is_valid=True
    )

@app.post("/api/verify", response_model=VerificationResponse)
def verify_license(request: VerificationRequest, db: Session = Depends(get_db), api_key: str = Depends(verify_api_key)):
    license_entry = db.query(License).filter(
        License.machine_id == request.machine_id,
        License.license_key == request.license_key
    ).first()

    if not license_entry:
        return VerificationResponse(is_valid=False, message="Licence invalide")

    if not license_entry.is_active:
        return VerificationResponse(is_valid=False, message="Licence désactivée")

    if license_entry.expires_at < datetime.utcnow():
        return VerificationResponse(is_valid=False, message="Licence expirée")

    return VerificationResponse(is_valid=True, message="Licence valide")

@app.get("/api/health")
def health_check():
    return {"status": "ok"}