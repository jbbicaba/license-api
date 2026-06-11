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
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin123")  # Mot de passe pour l’admin

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

# --- Migration automatique de la base de données ---
def migrate_database(engine):
    """Met à jour le schéma de la base de données si nécessaire."""
    inspector = inspect(engine)
    if not inspector.has_table("licenses"):
        return

    columns = [col['name'] for col in inspector.get_columns('licenses')]
    # Si la colonne 'id' n'existe pas, on doit recréer la table
    if 'id' not in columns:
        print("Ancienne version de la base détectée. Migration en cours...")
        with engine.connect() as conn:
            # 1. Renommer l'ancienne table
            conn.execute(text("ALTER TABLE licenses RENAME TO licenses_old"))
            conn.commit()

        # 2. Créer la nouvelle table avec le bon schéma
        Base.metadata.create_all(bind=engine)

        # 3. Copier les données existantes
        with engine.connect() as conn:
            conn.execute(text("""
                INSERT INTO licenses (machine_id, license_key, expires_at, is_active, created_at)
                SELECT machine_id, license_key, expires_at, is_active, created_at FROM licenses_old
            """))
            conn.commit()
            # 4. Supprimer l'ancienne table
            conn.execute(text("DROP TABLE licenses_old"))
            conn.commit()
        print("Migration terminée avec succès.")
    else:
        # Si la table a déjà 'id' mais pas les autres colonnes, on les ajoute
        with engine.connect() as conn:
            if 'customer_name' not in columns:
                conn.execute(text("ALTER TABLE licenses ADD COLUMN customer_name TEXT DEFAULT ''"))
            if 'notes' not in columns:
                conn.execute(text("ALTER TABLE licenses ADD COLUMN notes TEXT DEFAULT ''"))
            conn.commit()

# Exécuter la migration avant de créer les tables
migrate_database(engine)
Base.metadata.create_all(bind=engine)

# FastAPI
app = FastAPI(title="License Manager")

# Templates et fichiers statiques
templates = Jinja2Templates(directory="admin/templates")
if os.path.exists("admin/static"):
    app.mount("/static", StaticFiles(directory="admin/static"), name="static")

# Sécurité API (pour le logiciel)
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

# --- Endpoints API (pour le logiciel) ---
@app.post("/api/activate", response_model=LicenseResponse)
def activate_license(request: LicenseRequest, db: Session = Depends(get_db), api_key: str = Depends(verify_api_key)):
    existing = db.query(License).filter(License.machine_id == request.machine_id).first()
    if existing:
        return LicenseResponse(
            license_key=existing.license_key,
            expires_at=existing.expires_at,
            is_valid=existing.is_active and existing.expires_at > datetime.utcnow()
        )
    license_key = secrets.token_hex(16)
    expires_at = datetime.utcnow() + timedelta(days=365)
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

# --- Interface d’administration (web) ---
def verify_admin(request: Request, db: Session = Depends(get_db)):
    admin_auth = request.cookies.get("admin_auth")
    if admin_auth != ADMIN_PASSWORD:
        return None
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
    auth = request.cookies.get("admin_auth")
    if auth != ADMIN_PASSWORD:
        return RedirectResponse(url="/admin/login", status_code=302)
    licenses = db.query(License).all()
    return templates.TemplateResponse("dashboard.html", {"request": request, "licenses": licenses})

@app.get("/admin/license/new", response_class=HTMLResponse)
def new_license_form(request: Request, db: Session = Depends(get_db)):
    auth = request.cookies.get("admin_auth")
    if auth != ADMIN_PASSWORD:
        return RedirectResponse(url="/admin/login", status_code=302)
    return templates.TemplateResponse("edit_license.html", {"request": request, "license": None})

@app.post("/admin/license/new")
def create_license(
    request: Request,
    machine_id: str = Form(...),
    customer_name: str = Form(...),
    days_valid: int = Form(365),
    notes: str = Form(""),
    db: Session = Depends(get_db)
):
    auth = request.cookies.get("admin_auth")
    if auth != ADMIN_PASSWORD:
        return RedirectResponse(url="/admin/login", status_code=302)
    # Vérifier si machine_id existe déjà
    existing = db.query(License).filter(License.machine_id == machine_id).first()
    if existing:
        return templates.TemplateResponse("edit_license.html", {
            "request": request,
            "license": None,
            "error": "Ce machine_id existe déjà"
        })
    license_key = secrets.token_hex(16)
    expires_at = datetime.utcnow() + timedelta(days=days_valid)
    new_license = License(
        machine_id=machine_id,
        license_key=license_key,
        expires_at=expires_at,
        customer_name=customer_name,
        notes=notes
    )
    db.add(new_license)
    db.commit()
    return RedirectResponse(url="/admin/dashboard", status_code=302)

@app.get("/admin/license/{license_id}/edit", response_class=HTMLResponse)
def edit_license_form(request: Request, license_id: int, db: Session = Depends(get_db)):
    auth = request.cookies.get("admin_auth")
    if auth != ADMIN_PASSWORD:
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
    auth = request.cookies.get("admin_auth")
    if auth != ADMIN_PASSWORD:
        return RedirectResponse(url="/admin/login", status_code=302)
    license_entry = db.query(License).filter(License.id == license_id).first()
    if not license_entry:
        return RedirectResponse(url="/admin/dashboard", status_code=302)
    license_entry.customer_name = customer_name
    license_entry.notes = notes
    license_entry.is_active = is_active
    # Mettre à jour la date d'expiration
    new_expires = datetime.utcnow() + timedelta(days=days_valid)
    license_entry.expires_at = new_expires
    db.commit()
    return RedirectResponse(url="/admin/dashboard", status_code=302)

@app.get("/admin/license/{license_id}/revoke")
def revoke_license(request: Request, license_id: int, db: Session = Depends(get_db)):
    auth = request.cookies.get("admin_auth")
    if auth != ADMIN_PASSWORD:
        return RedirectResponse(url="/admin/login", status_code=302)
    license_entry = db.query(License).filter(License.id == license_id).first()
    if license_entry:
        license_entry.is_active = False
        db.commit()
    return RedirectResponse(url="/admin/dashboard", status_code=302)

@app.get("/admin/license/{license_id}/delete")
def delete_license(request: Request, license_id: int, db: Session = Depends(get_db)):
    auth = request.cookies.get("admin_auth")
    if auth != ADMIN_PASSWORD:
        return RedirectResponse(url="/admin/login", status_code=302)
    license_entry = db.query(License).filter(License.id == license_id).first()
    if license_entry:
        db.delete(license_entry)
        db.commit()
    return RedirectResponse(url="/admin/dashboard", status_code=302)