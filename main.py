import os
import secrets
from datetime import datetime, timedelta
from fastapi import FastAPI, HTTPException, Depends, Request, Form, status
from fastapi.security import APIKeyHeader
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, String, DateTime, Boolean, Integer, inspect, text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from dotenv import load_dotenv

load_dotenv()

# Configuration
SECRET_KEY = os.getenv("SECRET_KEY", "votre-clé-secrète")
API_KEY = os.getenv("API_KEY", "clé-api-pour-le-logiciel-client")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin123")

# Base de données
SQLALCHEMY_DATABASE_URL = "sqlite:///./licenses.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Modèle de licence
class License(Base):
    __tablename__ = "licenses"
    id = Column(Integer, primary_key=True, index=True)
    machine_id = Column(String, unique=True, index=True)
    license_key = Column(String, unique=True, index=True)
    expires_at = Column(DateTime)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    customer_name = Column(String, default="")
    notes = Column(String, default="")

# Modèle de clé produit (Product Key)
class ProductKey(Base):
    __tablename__ = "product_keys"
    id = Column(Integer, primary_key=True, index=True)
    key = Column(String, unique=True, index=True)
    is_used = Column(Boolean, default=False)
    used_by_machine_id = Column(String, nullable=True)
    customer_name = Column(String, default="")
    expires_at = Column(DateTime, nullable=True)  # None = illimité
    created_at = Column(DateTime, default=datetime.utcnow)

# Création des tables (avec gestion des erreurs si elles existent)
Base.metadata.create_all(bind=engine, checkfirst=True)

# FastAPI
app = FastAPI(title="License Manager")

# Templates et fichiers statiques
templates = Jinja2Templates(directory="admin/templates")
if os.path.exists("admin/static"):
    app.mount("/static", StaticFiles(directory="admin/static"), name="static")

# Sécurité API
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
class ActivateWithKeyRequest(BaseModel):
    product_key: str
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

# --- Endpoints API (pour le logiciel) ---
@app.post("/api/activate", response_model=LicenseResponse)
def activate_license(request: ActivateWithKeyRequest, db: Session = Depends(get_db), api_key: str = Depends(verify_api_key)):
    # Vérifier si cette machine a déjà une licence
    existing = db.query(License).filter(License.machine_id == request.machine_id).first()
    if existing:
        return LicenseResponse(
            license_key=existing.license_key,
            expires_at=existing.expires_at,
            is_valid=existing.is_active and existing.expires_at > datetime.utcnow()
        )
    
    # Vérifier la clé produit
    key_entry = db.query(ProductKey).filter(ProductKey.key == request.product_key).first()
    if not key_entry:
        raise HTTPException(status_code=400, detail="Clé produit invalide")
    if key_entry.is_used:
        raise HTTPException(status_code=400, detail="Clé déjà utilisée")
    if key_entry.expires_at and key_entry.expires_at < datetime.utcnow():
        raise HTTPException(status_code=400, detail="Clé expirée")
    
    # Marquer la clé comme utilisée
    key_entry.is_used = True
    key_entry.used_by_machine_id = request.machine_id
    
    # Créer la licence
    license_key = secrets.token_hex(16)
    expires_at = key_entry.expires_at or (datetime.utcnow() + timedelta(days=36500))  # 100 ans
    new_license = License(
        machine_id=request.machine_id,
        license_key=license_key,
        expires_at=expires_at,
        customer_name=key_entry.customer_name
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

# --- Interface d’administration (web) ---
def verify_admin(request: Request):
    admin_auth = request.cookies.get("admin_auth")
    if admin_auth != ADMIN_PASSWORD:
        return False
    return True

@app.get("/admin/login", response_class=HTMLResponse)
def admin_login_form(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@app.post("/admin/login")
def admin_login(request: Request, password: str = Form(...)):
    if password == ADMIN_PASSWORD:
        response = RedirectResponse(url="/admin/dashboard", status_code=302)
        response.set_cookie(key="admin_auth", value=password, httponly=True)
        return response
    return templates.TemplateResponse("login.html", {"request": request, "error": "Mot de passe incorrect"})

@app.get("/admin/dashboard", response_class=HTMLResponse)
def admin_dashboard(request: Request, db: Session = Depends(get_db)):
    if not verify_admin(request):
        return RedirectResponse(url="/admin/login", status_code=302)
    licenses = db.query(License).all()
    return templates.TemplateResponse("dashboard.html", {"request": request, "licenses": licenses})

@app.get("/admin/keys", response_class=HTMLResponse)
def admin_keys_page(request: Request, db: Session = Depends(get_db)):
    if not verify_admin(request):
        return RedirectResponse(url="/admin/login", status_code=302)
    keys = db.query(ProductKey).all()
    return templates.TemplateResponse("keys.html", {"request": request, "keys": keys})

@app.post("/admin/generate_key")
def generate_key(request: Request, customer_name: str = Form(...), days_valid: int = Form(0), db: Session = Depends(get_db)):
    if not verify_admin(request):
        return RedirectResponse(url="/admin/login", status_code=302)
    new_key = secrets.token_hex(16).upper()
    expires_at = None
    if days_valid > 0:
        expires_at = datetime.utcnow() + timedelta(days=days_valid)
    product_key = ProductKey(
        key=new_key,
        customer_name=customer_name,
        expires_at=expires_at
    )
    db.add(product_key)
    db.commit()
    return RedirectResponse(url="/admin/keys", status_code=302)

@app.get("/admin/logout")
def admin_logout(request: Request):
    response = RedirectResponse(url="/admin/login", status_code=302)
    response.delete_cookie("admin_auth")
    return response

# Ajouter une route pour voir les licences et les clés (optionnel)
@app.get("/admin/license/{license_id}/edit", response_class=HTMLResponse)
def edit_license_form(request: Request, license_id: int, db: Session = Depends(get_db)):
    if not verify_admin(request):
        return RedirectResponse(url="/admin/login", status_code=302)
    license_entry = db.query(License).filter(License.id == license_id).first()
    if not license_entry:
        return RedirectResponse(url="/admin/dashboard", status_code=302)
    return templates.TemplateResponse("edit_license.html", {"request": request, "license": license_entry})

@app.post("/admin/license/{license_id}/edit")
def update_license(
    request: Request,
    license_id: int,
    customer_name: str = Form(...),
    days_valid: int = Form(...),
    is_active: bool = Form(False),
    notes: str = Form(""),
    db: Session = Depends(get_db)
):
    if not verify_admin(request):
        return RedirectResponse(url="/admin/login", status_code=302)
    license_entry = db.query(License).filter(License.id == license_id).first()
    if not license_entry:
        return RedirectResponse(url="/admin/dashboard", status_code=302)
    license_entry.customer_name = customer_name
    license_entry.notes = notes
    license_entry.is_active = is_active
    new_expires = datetime.utcnow() + timedelta(days=days_valid)
    license_entry.expires_at = new_expires
    db.commit()
    return RedirectResponse(url="/admin/dashboard", status_code=302)

@app.get("/admin/license/{license_id}/revoke")
def revoke_license(request: Request, license_id: int, db: Session = Depends(get_db)):
    if not verify_admin(request):
        return RedirectResponse(url="/admin/login", status_code=302)
    license_entry = db.query(License).filter(License.id == license_id).first()
    if license_entry:
        license_entry.is_active = False
        db.commit()
    return RedirectResponse(url="/admin/dashboard", status_code=302)

@app.get("/admin/license/{license_id}/delete")
def delete_license(request: Request, license_id: int, db: Session = Depends(get_db)):
    if not verify_admin(request):
        return RedirectResponse(url="/admin/login", status_code=302)
    license_entry = db.query(License).filter(License.id == license_id).first()
    if license_entry:
        db.delete(license_entry)
        db.commit()
    return RedirectResponse(url="/admin/dashboard", status_code=302)