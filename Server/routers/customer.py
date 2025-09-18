from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, EmailStr, field_validator
from sqlmodel import Session, select

from ..core.security import sanitize_input
from ..core.jwt_handler import get_current_user

from ..db.session import get_session
from ..db.models.customer import Customer
from ..db.models.user import User
from ..db.models.plan import Plan

router = APIRouter(prefix="/api/v1/customers", tags=["customers"])


class CustomerCreateIn(BaseModel):
    full_name: str
    email: EmailStr
    phone: str
    plan_id: Optional[int] = None

    @field_validator("full_name")
    @classmethod
    def _sanitize_full_name(cls, v: str) -> str:
        v = sanitize_input(v)
        if len(v) == 0 or len(v) > 255:
            raise ValueError("Full name must be non-empty and up to 255 chars")
        return v

    @field_validator("email")
    @classmethod
    def _normalize_email(cls, v: EmailStr) -> str:
        return str(v).lower().strip()

    @field_validator("phone")
    @classmethod
    def _sanitize_phone(cls, v: str) -> str:
        v = sanitize_input(v)
        if len(v) > 20:
            raise ValueError("Phone number too long")
        return v


class CustomerUpdateIn(BaseModel):
    full_name: Optional[str] = None
    email: Optional[EmailStr] = None
    phone: Optional[str] = None
    plan_id: Optional[int] = None
    active: Optional[bool] = None

    @field_validator("full_name")
    @classmethod
    def _sanitize_full_name(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        v = sanitize_input(v)
        if len(v) > 255:
            raise ValueError("Full name too long")
        return v

    @field_validator("email")
    @classmethod
    def _normalize_email(cls, v: Optional[EmailStr]) -> Optional[str]:
        return str(v).lower().strip() if v is not None else v

    @field_validator("phone")
    @classmethod
    def _sanitize_phone(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        v = sanitize_input(v)
        if len(v) > 20:
            raise ValueError("Phone number too long")
        return v


@router.post("", response_model=Customer)
def create_customer(payload: CustomerCreateIn, current_user: User = Depends(get_current_user), db: Session = Depends(get_session)):
    if payload.plan_id is not None:
        if not db.exec(select(Plan).where(Plan.id == payload.plan_id)).first():
            raise HTTPException(status_code=400, detail="plan_id not found")

    if db.exec(select(Customer).where(Customer.email == payload.email)).first() \
            or db.exec(select(User).where(User.email == payload.email)).first():
        raise HTTPException(status_code=400, detail="Email already exists")

    if db.exec(select(Customer).where(Customer.full_name == payload.full_name)).first() \
            or db.exec(select(User).where(User.username == payload.full_name)).first():
        raise HTTPException(status_code=400, detail="Full name already exists")

    cust = Customer(
        full_name=payload.full_name,
        email=payload.email,
        phone=payload.phone,
        plan_id=payload.plan_id,
    )
    db.add(cust)
    db.commit()
    db.refresh(cust)
    return cust


@router.get("", response_model=List[Customer])
def list_customers(current_user: User = Depends(get_current_user),
    db: Session = Depends(get_session)):
    return db.exec(select(Customer)).all()


@router.get("/{customer_id}", response_model=Customer)
def get_customer(customer_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_session)):
    cust = db.get(Customer, customer_id)
    if not cust:
        raise HTTPException(status_code=404, detail="Customer not found")
    return cust


@router.put("/{customer_id}", response_model=Customer)
def update_customer(customer_id: int, data: CustomerUpdateIn, db: Session = Depends(get_session)):
    cust = db.get(Customer, customer_id)
    if not cust:
        raise HTTPException(status_code=404, detail="Customer not found")

    if data.email is not None:
        cust.email = data.email
    if data.full_name is not None:
        cust.full_name = data.full_name
    if data.phone is not None:
        cust.phone = data.phone
    if data.plan_id is not None:
        if not db.exec(select(Plan).where(Plan.id == data.plan_id)).first():
            raise HTTPException(status_code=400, detail="plan_id not found")
        cust.plan_id = data.plan_id
    if data.active is not None:
        cust.active = data.active

    db.add(cust)
    db.commit()
    db.refresh(cust)
    return cust


@router.delete("/{customer_id}")
def delete_customer(customer_id: int, db: Session = Depends(get_session)):
    cust = db.get(Customer, customer_id)
    if not cust:
        raise HTTPException(status_code=404, detail="Customer not found")
    db.delete(cust)
    db.commit()
    return {"deleted": customer_id}

@router.get("/search/{name}", response_model=List[Customer])
def search_customer_by_name(name: str, current_user: User = Depends(get_current_user),
                            db: Session = Depends(get_session)):
    sanitized_name = sanitize_input(name)
    if not sanitized_name:
        raise HTTPException(status_code=400, detail="Name cannot be empty")

    customers = db.exec(
        select(Customer).where(Customer.full_name.ilike(f"%{sanitized_name}%"))
    ).all()

    return customers