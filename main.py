from fastapi import FastAPI, Request, Form, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, Integer, String, Boolean, DateTime, func
from sqlalchemy.orm import DeclarativeBase, Session
from datetime import datetime, timedelta
import uvicorn
import secrets

import os

from starlette.middleware.sessions import SessionMiddleware

import hashlib

import smtplib
from email.message import EmailMessage
# ── Database setup ──────────────────────────────────────────────────────────
DATABASE_URL = "sqlite:///./rfid.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})

class Base(DeclarativeBase):
    pass

class Card(Base):
    __tablename__ = "cards"
    id          = Column(Integer, primary_key=True, index=True)
    rfid_number = Column(String, unique=True, index=True, nullable=False)
    name        = Column(String, nullable=False)
    is_active   = Column(Boolean, default=True)
    created_at  = Column(DateTime, default=datetime.utcnow)

class ScanLog(Base):
    __tablename__ = "scan_logs"
    id          = Column(Integer, primary_key=True, index=True)
    rfid_number = Column(String, nullable=False)
    user_name   = Column(String, nullable=True)   # null = unknown card
    access      = Column(Boolean, nullable=False)
    scanned_at  = Column(DateTime, default=datetime.utcnow)

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)

    full_name = Column(String, nullable=False)

    email = Column(
        String,
        unique=True,
        index=True,
        nullable=False
    )

    password_hash = Column(String, nullable=False)
    password_salt = Column(String, nullable=False)

    role = Column(String, nullable=False, default="student")

    is_active = Column(Boolean, default=True)

    created_at = Column(
        DateTime,
        default=datetime.utcnow
    )

# new class for reservations
class Reservation(Base):
    __tablename__ = "reservations"

    id = Column(Integer, primary_key=True, index=True)
    user_name = Column(String, nullable=False)
    email = Column(String, nullable=False)
    pin = Column(String, unique=True, index=True, nullable=False)

    start_time = Column(DateTime, nullable=False)
    end_time = Column(DateTime, nullable=False)

    equipment = Column(String, nullable=True)
    comment = Column(String, nullable=True)

    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)

class PinAccessLog(Base):
    __tablename__ = "pin_access_logs"

    id = Column(Integer, primary_key=True, index=True)
    user_name = Column(String, nullable=True)
    reservation_id = Column(Integer, nullable=True)
    access = Column(Boolean, nullable=False)
    attempted_at = Column(DateTime, default=datetime.utcnow)

class EmailVerification(Base):
    __tablename__ = "email_verifications"

    id = Column(Integer, primary_key=True, index=True)

    full_name = Column(String, nullable=False)
    email = Column(String, index=True, nullable=False)

    password_hash = Column(String, nullable=False)
    password_salt = Column(String, nullable=False)

    token_hash = Column(String, nullable=False)

    expires_at = Column(DateTime, nullable=False)

    created_at = Column(
        DateTime,
        default=datetime.utcnow
    )

Base.metadata.create_all(bind=engine)

# ── App setup ────────────────────────────────────────────────────────────────
app = FastAPI(title="RFID Access Control")
SESSION_SECRET = os.getenv(
    "SESSION_SECRET",
    "dev-secret-change-this-later"
)

app.add_middleware(
    SessionMiddleware,
    secret_key=SESSION_SECRET,
    same_site="lax",
    https_only=False
)

templates = Jinja2Templates(directory="templates")

def hash_password(password: str, salt: str = None):
    if salt is None:
        salt = secrets.token_hex(16)

    password_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode(),
        salt.encode(),
        200_000
    ).hex()

    return password_hash, salt


def verify_password(password: str, password_hash: str, salt: str):
    test_hash, _ = hash_password(password, salt)

    return secrets.compare_digest(
        test_hash,
        password_hash
    )

def send_verification_email(recipient_email: str, verification_link: str):
    sender_email = os.getenv("MAIL_USERNAME")
    sender_password = os.getenv("MAIL_PASSWORD")

    if not sender_email or not sender_password:
        raise RuntimeError("Email credentials are not configured.")

    message = EmailMessage()

    message["Subject"] = "RAF Lab - Verify your account"
    message["From"] = sender_email
    message["To"] = recipient_email

    message.set_content(
        f"""
Hello,

A registration request was made for the RAF Lab Access System.

To verify your RAF email address and create your account, open this link:

{verification_link}

This link expires in 15 minutes.

If you did not request this account, ignore this email.
"""
    )

    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
        smtp.login(sender_email, sender_password)
        smtp.send_message(message)

def get_current_user(request: Request):
    user_id = request.session.get("user_id")

    if not user_id:
        return None

    with Session(engine) as db:
        user = db.query(User).filter(
            User.id == user_id,
            User.is_active == True
        ).first()

        return user

def get_admin_user(request: Request):
    user = get_current_user(request)

    if not user:
        return None

    if user.role != "admin":
        return None

    return user

def get_db():
    with Session(engine) as db:
        yield db

# ── Pydantic model for ESP32 ─────────────────────────────────────────────────
class RFIDCheckRequest(BaseModel):
    rfid_number: str

class PinCheckRequest(BaseModel):
    pin: str    

# ══════════════════════════════════════════════════════════════════════════════
#  API ENDPOINT  –  called by the ESP32
# ══════════════════════════════════════════════════════════════════════════════
@app.post("/functions/v1/rfid-api/check")
async def check_rfid(payload: RFIDCheckRequest):
    rfid = payload.rfid_number.upper().strip()

    with Session(engine) as db:
        card = db.query(Card).filter(
            Card.rfid_number == rfid,
            Card.is_active == True
        ).first()

        access_granted = card is not None
        user_name = card.name if card else None

        log = ScanLog(
            rfid_number=rfid,
            user_name=user_name,
            access=access_granted,
        )

        db.add(log)
        db.commit()

    if access_granted:
        return {
            "access_granted": True,
            "user": {"name": user_name}
        }

    return {"access_granted": False}

# updated app.post
@app.post("/api/access/check")
async def check_pin(payload: PinCheckRequest):
    pin = payload.pin.strip()
    now = datetime.now()

    with Session(engine) as db:
        reservation = db.query(Reservation).filter(
            Reservation.pin == pin,
            Reservation.is_active == True,
            Reservation.start_time <= now,
            Reservation.end_time >= now
        ).first()

        access_granted = reservation is not None

        log = PinAccessLog(
            user_name=reservation.user_name if reservation else None,
            reservation_id=reservation.id if reservation else None,
            access=access_granted
        )

        db.add(log)
        db.commit()

        if access_granted:
            return {
                "access_granted": True,
                "user": reservation.user_name,
                "reservation_id": reservation.id
            }

    return {
        "access_granted": False
    }

@app.get("/api/calendar/events")
async def calendar_events(request: Request):
    user = get_current_user(request)

    if not user:
        raise HTTPException(
            status_code=401,
            detail="You must be logged in."
        )

    with Session(engine) as db:
        reservations = (
            db.query(Reservation)
            .filter(Reservation.is_active == True)
            .order_by(Reservation.start_time.asc())
            .all()
        )

        events = []

        for reservation in reservations:

            if user.role == "admin":
                title = reservation.user_name

            elif reservation.email == user.email:
                title = "MY RESERVATION"

            else:
                title = "RESERVED"

            events.append({
                "id": reservation.id,
                "title": title,
                "start": reservation.start_time.isoformat(),
                "end": reservation.end_time.isoformat()
            })

    return events

@app.post("/reservations/add", response_class=HTMLResponse)
async def add_reservation(
    request: Request,
    start_time: str = Form(...),
    end_time: str = Form(...),
    equipment: str = Form(""),
    comment: str = Form("")
):
    user = get_current_user(request)

    if not user:
        return HTMLResponse(
            '<div style="color:#ff5d73;">You must be logged in.</div>',
            status_code=401
        )

    start = datetime.fromisoformat(start_time)
    end = datetime.fromisoformat(end_time)

    if end <= start:
        return HTMLResponse(
            '<div style="color:#ff5d73;">End time must be after start time.</div>'
        )

    with Session(engine) as db:

        # Provera preklapanja termina
        conflict = db.query(Reservation).filter(
            Reservation.is_active == True,
            Reservation.start_time < end,
            Reservation.end_time > start
        ).first()

        if conflict:
            return HTMLResponse(
                '''
                <div style="
                    padding:1rem;
                    border:1px solid #ff5d73;
                    background:rgba(255,93,115,.08);
                    border-radius:6px;
                    color:#ff5d73;
                ">
                    THIS TIME SLOT IS ALREADY RESERVED.
                </div>
                '''
            )

        # Generisanje jedinstvenog PIN-a
        while True:
            pin = f"{secrets.randbelow(1000000):06d}"

            existing = db.query(Reservation).filter(
                Reservation.pin == pin
            ).first()

            if not existing:
                break

        # Kreiranje rezervacije
        reservation = Reservation(
            user_name=user.full_name,
            email=user.email,
            pin=pin,
            start_time=start,
            end_time=end,
            equipment=equipment.strip(),
            comment=comment.strip(),
            is_active=True
        )

        db.add(reservation)
        db.commit()
        db.refresh(reservation)

    return HTMLResponse(
        f'''
        <div style="
            padding:1rem;
            border:1px solid #7c6cff;
            background:rgba(124,108,255,.08);
            border-radius:6px;
        ">
            <div style="color:#8490ad; font-size:.8rem;">
                RESERVATION CREATED
            </div>

            <div style="
                color:#e7eaff;
                font-size:1rem;
                margin-top:.4rem;
            ">
                {reservation.user_name}
            </div>

            <div style="
                color:#7c6cff;
                font-size:1.8rem;
                font-weight:bold;
                margin-top:.5rem;
            ">
                PIN: {pin}
            </div>

            <div style="color:#8490ad; margin-top:.3rem;">
                {start.strftime("%d.%m.%Y %H:%M")}
                —
                {end.strftime("%d.%m.%Y %H:%M")}
            </div>
        </div>
        '''
    )

@app.get("/register", response_class=HTMLResponse)
async def register_page(request: Request):
    return templates.TemplateResponse(
        request,
        "register.html",
        {
            "error": None,
            "success": None
        }
    )

@app.post("/register", response_class=HTMLResponse)
async def register_user(
    request: Request,
    full_name: str = Form(...),
    email: str = Form(...),
    password: str = Form(...)
):
    full_name = full_name.strip()
    email = email.strip().lower()

    # Dozvoljeni su samo RAF nalozi
    if not email.endswith("@raf.rs"):
        return templates.TemplateResponse(
            request,
            "register.html",
            {
                "error": "Registration is allowed only with a @raf.rs email address.",
                "success": None
            }
        )

    if len(password) < 8:
        return templates.TemplateResponse(
            request,
            "register.html",
            {
                "error": "Password must contain at least 8 characters.",
                "success": None
            }
        )

    with Session(engine) as db:

        # Da li nalog već postoji?
        existing_user = db.query(User).filter(
            User.email == email
        ).first()

        if existing_user:
            return templates.TemplateResponse(
                request,
                "register.html",
                {
                    "error": "An account with this email already exists.",
                    "success": None
                }
            )

        # Brišemo eventualni prethodni nepotvrđeni zahtev
        db.query(EmailVerification).filter(
            EmailVerification.email == email
        ).delete()

        # Hashujemo password kao i ranije
        password_hash, salt = hash_password(password)

        # Ovo je token koji će korisnik dobiti u email linku
        verification_token = secrets.token_urlsafe(32)

        # U bazu ne čuvamo originalni token
        token_hash = hashlib.sha256(
            verification_token.encode()
        ).hexdigest()

        verification = EmailVerification(
            full_name=full_name,
            email=email,
            password_hash=password_hash,
            password_salt=salt,
            token_hash=token_hash,
            expires_at=datetime.utcnow() + timedelta(minutes=15)
        )

        db.add(verification)
        db.commit()
        db.refresh(verification)

        verification_link = (
            f"http://127.0.0.1:8000/verify-email"
            f"?id={verification.id}"
            f"&token={verification_token}"
        )

        # SAMO ZA DEVELOPMENT
        print("\nEMAIL VERIFICATION LINK:")
        print(verification_link)
        print()

        send_verification_email(
        email,
        verification_link
    )

    return templates.TemplateResponse(
        request,
        "register.html",
        {
            "error": None,
            "success": "Verification link sent. Check your RAF email."
        }
    )

@app.get("/verify-email")
async def verify_email(
    verification_id: int = None,
    id: int = None,
    token: str = ""
):
    # Koristimo id iz verification linka
    verification_id = id

    if not verification_id or not token:
        raise HTTPException(
            status_code=400,
            detail="Invalid verification link."
        )

    token_hash = hashlib.sha256(
        token.encode()
    ).hexdigest()

    with Session(engine) as db:

        verification = db.query(EmailVerification).filter(
            EmailVerification.id == verification_id
        ).first()

        if not verification:
            raise HTTPException(
                status_code=400,
                detail="Verification request not found."
            )

        # Token istekao
        if datetime.utcnow() > verification.expires_at:
            db.delete(verification)
            db.commit()

            raise HTTPException(
                status_code=400,
                detail="Verification link has expired."
            )

        # Proveravamo token
        if not secrets.compare_digest(
            token_hash,
            verification.token_hash
        ):
            raise HTTPException(
                status_code=400,
                detail="Invalid verification token."
            )

        # Proveravamo još jednom da nalog nije u međuvremenu napravljen
        existing_user = db.query(User).filter(
            User.email == verification.email
        ).first()

        if existing_user:
            db.delete(verification)
            db.commit()

            return RedirectResponse(
                url="/login?verified=1",
                status_code=303
            )

        # TEK OVDE nastaje pravi nalog
        user = User(
            full_name=verification.full_name,
            email=verification.email,
            password_hash=verification.password_hash,
            password_salt=verification.password_salt,
            role="student",
            is_active=True
        )

        db.add(user)

        # Token postaje neupotrebljiv
        db.delete(verification)

        db.commit()

    return RedirectResponse(
        url="/login?verified=1",        
        status_code=303
    )

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    verified = request.query_params.get("verified")

    success_message = None

    if verified == "1":
        success_message = "Email verified successfully. You can now log in."

    return templates.TemplateResponse(
        request,
        "login.html",
        {
            "error": None,
            "success": success_message
        }
    )

@app.post("/login", response_class=HTMLResponse)
async def login_user(
    request: Request,
    email: str = Form(...),
    password: str = Form(...)
):
    email = email.strip().lower()

    with Session(engine) as db:

        user = db.query(User).filter(
            User.email == email,
            User.is_active == True
        ).first()

        if not user:
            return templates.TemplateResponse(
                request,
                "login.html",
                {
                    "error": "Invalid email or password.",
                    "success": None
                }
            )

        password_ok = verify_password(
        password,
        user.password_hash,
        user.password_salt
    )

    if not password_ok:
        return templates.TemplateResponse(
            request,
            "login.html",
            {
                "error": "Invalid email or password.",
                "success": None
            }
        )

    request.session["user_id"] = user.id

    if user.role == "admin":
        return RedirectResponse(
            url="/admin",
            status_code=303
        )

    return RedirectResponse(
        url="/student",
        status_code=303
    )

# ══════════════════════════════════════════════════════════════════════════════
#  WEB DASHBOARD
# ══════════════════════════════════════════════════════════════════════════════

# ispravljen student endpoint
@app.get("/", response_class=HTMLResponse)
async def student_dashboard(request: Request):
    return templates.TemplateResponse(
        request,
        "dashboard.html",
        {
            "is_admin": False
        }
    )

@app.get("/student", response_class=HTMLResponse)
async def student_dashboard_logged_in(request: Request):

    user = get_current_user(request)

    if not user:
        return RedirectResponse(
            url="/login",
            status_code=303
        )

    now = datetime.now()

    with Session(engine) as db:
        reservations = (
            db.query(Reservation)
            .filter(Reservation.email == user.email)
            .order_by(Reservation.start_time.desc())
            .all()
        )

    return templates.TemplateResponse(
        request,
        "dashboard.html",
        {
            "is_admin": False,
            "user": user,
            "reservations": reservations,
            "now": now
        }
    )

@app.get("/logout")
async def logout(request: Request):
    request.session.clear()

    return RedirectResponse(
        url="/login",
        status_code=303
    )

# novi admin endpoint
@app.get("/admin", response_class=HTMLResponse)
async def admin_dashboard(request: Request):

    user = get_admin_user(request)

    if not user:
        return RedirectResponse(
            url="/login",
            status_code=303
        )

    now = datetime.now()

    with Session(engine) as db:
        users = (
            db.query(User)
            .order_by(User.created_at.desc())
            .all()
        )

        reservations = (
            db.query(Reservation)
            .order_by(Reservation.start_time.asc())
            .all()
        )

        access_logs = (
            db.query(PinAccessLog)
            .order_by(PinAccessLog.attempted_at.desc())
            .limit(50)
            .all()
        )

        total = db.query(func.count(Reservation.id)).scalar()

        active = db.query(func.count(Reservation.id)).filter(
            Reservation.is_active == True,
            Reservation.start_time <= now,
            Reservation.end_time >= now
        ).scalar()

        granted = db.query(func.count(PinAccessLog.id)).filter(
            PinAccessLog.access == True
        ).scalar()

        denied = db.query(func.count(PinAccessLog.id)).filter(
            PinAccessLog.access == False
        ).scalar()

    return templates.TemplateResponse(
        request,
        "dashboard.html",
        {
            "is_admin": True,
            "user": user,
            "users": users,
            "reservations": reservations,
            "access_logs": access_logs,
            "total": total,
            "active": active,
            "granted": granted,
            "denied": denied,
            "now": now
        }
    )

@app.post("/admin/users/{user_id}/delete")
async def delete_user_account(
    request: Request,
    user_id: int
):
    admin = get_admin_user(request)

    if not admin:
        return RedirectResponse(
            url="/login",
            status_code=303
        )

    # Admin ne sme slučajno da obriše sam sebe
    if admin.id == user_id:
        raise HTTPException(
            status_code=400,
            detail="You cannot delete your own admin account."
        )

    with Session(engine) as db:

        target_user = db.query(User).filter(
            User.id == user_id
        ).first()

        if not target_user:
            raise HTTPException(
                status_code=404,
                detail="User not found."
            )

        db.delete(target_user)
        db.commit()

    return RedirectResponse(
        url="/admin",
        status_code=303
    )

# ── Cards HTMX partials ──────────────────────────────────────────────────────

@app.post("/cards/add", response_class=HTMLResponse)
async def add_card(request: Request,
                   rfid_number: str = Form(...),
                   name: str = Form(...)):
    rfid = rfid_number.upper().strip()
    with Session(engine) as db:
        existing = db.query(Card).filter(Card.rfid_number == rfid).first()
        if existing:
            # Return an error row
            return HTMLResponse(
                f'<tr id="error-row"><td colspan="5" class="error-msg">'
                f'⚠ Card {rfid} already exists!</td></tr>',
                status_code=200
            )
        card = Card(rfid_number=rfid, name=name.strip())
        db.add(card)
        db.commit()
        db.refresh(card)

    return templates.TemplateResponse(request, "partials/card_row.html",
                                      {"card": card})


@app.delete("/cards/{card_id}", response_class=HTMLResponse)
async def delete_card(card_id: int):
    with Session(engine) as db:
        card = db.query(Card).filter(Card.id == card_id).first()
        if not card:
            raise HTTPException(status_code=404, detail="Card not found")
        db.delete(card)
        db.commit()
    return HTMLResponse("")   # HTMX swaps the row with nothing


@app.patch("/cards/{card_id}/toggle", response_class=HTMLResponse)
async def toggle_card(request: Request, card_id: int):
    with Session(engine) as db:
        card = db.query(Card).filter(Card.id == card_id).first()
        if not card:
            raise HTTPException(status_code=404, detail="Card not found")
        card.is_active = not card.is_active
        db.commit()
        db.refresh(card)

    return templates.TemplateResponse(request, "partials/card_row.html",
                                      {"card": card})


# ── Logs HTMX partial ────────────────────────────────────────────────────────

@app.get("/logs/refresh", response_class=HTMLResponse)
async def refresh_logs(request: Request):
    with Session(engine) as db:
        logs = db.query(ScanLog).order_by(ScanLog.scanned_at.desc()).limit(50).all()
    return templates.TemplateResponse(request, "partials/log_rows.html",
                                      {"logs": logs})


if __name__ == "__main__":
    uvicorn.run(
        app,
        host="127.0.0.1",
        port=8000,
        reload=False
    )
