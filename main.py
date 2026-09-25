from fastapi import FastAPI, Request, Form, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, Integer, String, Boolean, DateTime, func
from sqlalchemy.orm import DeclarativeBase, Session
from datetime import datetime
import uvicorn
import secrets

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

Base.metadata.create_all(bind=engine)

# ── App setup ────────────────────────────────────────────────────────────────
app = FastAPI(title="RFID Access Control")
templates = Jinja2Templates(directory="templates")

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

@app.post("/reservations/add", response_class=HTMLResponse)
async def add_reservation(
    user_name: str = Form(...),
    email: str = Form(...),
    start_time: str = Form(...),
    end_time: str = Form(...),
    equipment: str = Form(""),
    comment: str = Form("")
):
    start = datetime.fromisoformat(start_time)
    end = datetime.fromisoformat(end_time)

    if end <= start:
        return HTMLResponse(
            '<div style="color:#ff5d73;">End time must be after start time.</div>'
        )

    with Session(engine) as db:

        while True:
            pin = f"{secrets.randbelow(1000000):06d}"

            existing = db.query(Reservation).filter(
                Reservation.pin == pin
            ).first()

            if not existing:
                break

        reservation = Reservation(
            user_name=user_name.strip(),
            email=email.strip(),
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

# ══════════════════════════════════════════════════════════════════════════════
#  WEB DASHBOARD
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    now = datetime.now()

    with Session(engine) as db:
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

    return templates.TemplateResponse(request, "dashboard.html", {
        "reservations": reservations,
        "access_logs": access_logs,
        "total": total,
        "active": active,
        "granted": granted,
        "denied": denied,
        "now": now
    })


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
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
