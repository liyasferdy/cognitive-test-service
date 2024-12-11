from pydantic import BaseModel
from passlib.context import CryptContext
from sqlalchemy import Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from typing import Optional, List
import os
import jwt
from datetime import datetime, timedelta
from jose import JWTError
from sqlalchemy import create_engine, text, Column, Integer, String, ForeignKey, JSON, TIMESTAMP
from sqlalchemy.sql import func
from fastapi import HTTPException
from dotenv import load_dotenv
import os

# Load environment variables from .env file
load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")  # Ambil URL dari environment


# Secret key untuk JWT encoding dan decoding
SECRET_KEY = os.getenv("SECRET_KEY", "mysecretkey")  # Set a default for development
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60


# Inisialisasi engine dan session untuk SQLAlchemy
engine = create_engine(DATABASE_URL, echo=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Base untuk model SQLAlchemy
Base = declarative_base()

# Password hashing using passlib
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Model untuk Registrasi Pengguna
class UserCreate(BaseModel):
    username: str
    password: str

class User(BaseModel):
    username: str

    class Config:
        orm_mode = True  # Enable ORM mode untuk Pydantic bekerja dengan SQLAlchemy


# Model untuk tabel pengguna (menggunakan SQLAlchemy)
class UserInDB(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    password = Column(String)
    token = Column(String, nullable=True)  # Menyimpan token JWT


class UsersData(Base):
    __tablename__ = "users_data"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, ForeignKey("users.username"), nullable=False)
    nama = Column(String, nullable=False)
    usia = Column(Integer, nullable=False)
    jenis_kelamin = Column(String, nullable=False)
    domisili = Column(String, nullable=False)
    pendidikan_terakhir = Column(String, nullable=False)
    suku = Column(String, nullable=False)
    created_at = Column(String, default=datetime.utcnow)


# Model untuk tabel test_MV
class TestMV(Base):
    __tablename__ = "test_MV"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, ForeignKey("users_data.username"), nullable=False)
    nama = Column(String, ForeignKey("users_data.nama"), nullable=False)
    answers = Column(JSON, nullable=False)  # Menyimpan jawaban dalam format JSON
    created_at = Column(TIMESTAMP, server_default=func.now())  # Timestamp otomatis


# Fungsi untuk mendapatkan sesi database
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# Hash password
def hash_password(password: str) -> str:
    """Hash the plain password."""
    return pwd_context.hash(password)

# Verifikasi password
def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify that the plain password matches the hashed password."""
    return pwd_context.verify(plain_password, hashed_password)

# Fungsi untuk membuat JWT token
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Create a JWT token."""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


# Fungsi untuk mendapatkan user berdasarkan username
def get_user_by_username(db: Session, username: str):
    """
    Mendapatkan user dari tabel users (UserInDB).
    """
    return db.query(UserInDB).filter(UserInDB.username == username).first()



def is_username_taken(db: Session, username: str) -> bool:
    """
    Periksa apakah username sudah ada di database.
    """
    return db.query(UserInDB).filter(UserInDB.username == username).first() is not None


def get_user_from_token(token: str, db: Session):
    """
    Mengambil data pengguna dari token JWT yang valid.
    """
    try:
        # Decode JWT token
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Token tidak valid")

        # Cek apakah token ada di database
        db_user = db.query(UserInDB).filter(UserInDB.username == username).first()
        if db_user is None or db_user.token != token:
            raise HTTPException(status_code=401, detail="Token tidak valid atau sudah kadaluarsa")

        return db_user
    except JWTError:
        raise HTTPException(status_code=401, detail="Token tidak valid")
    


# Fungsi untuk mendapatkan user berdasarkan user_data
def get_user_by_user_data(db: Session, username: str):
    """
    Mendapatkan user dari tabel users (UserInDB).
    """
    return db.query(UsersData).filter(UsersData.username == username).first()

# Fungsi untuk membuat pengguna baru (registrasi)
def create_user(db: Session, user: UserCreate):
    hashed_password = hash_password(user.password)
    db_user = UserInDB(username=user.username, password=hashed_password)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

# Fungsi untuk menyimpan token ke dalam tabel users
def save_token(db: Session, username: str, token: str):
    db_user = db.query(UserInDB).filter(UserInDB.username == username).first()
    if db_user:
        db_user.token = token  # Update token pada pengguna
        db.commit()
        db.refresh(db_user)
        return db_user
    return None

def delete_token(db: Session, username: str):
    db.query(UserInDB).filter(UserInDB.username == username).update({"token": None})
    db.commit()
    

# Save users_data on db w/ ForeignKey
def create_user_data(db: Session, username: str, nama: str, usia: int, jenis_kelamin: str, domisili: str, pendidikan_terakhir: str, suku: str):
    """Menyimpan data tambahan pengguna."""
    user_exists = db.query(UserInDB).filter(UserInDB.username == username).first()
    if not user_exists:
        raise ValueError("Username tidak ditemukan di tabel users")
    query = text("""
        INSERT INTO users_data (username, nama, usia, jenis_kelamin, domisili, pendidikan_terakhir, suku)
        VALUES (:username, :nama, :usia, :jenis_kelamin, :domisili, :pendidikan_terakhir, :suku)
    """)
    db.execute(query, {
        "username": username,
        "nama": nama,
        "usia": usia,
        "jenis_kelamin": jenis_kelamin,
        "domisili": domisili,
        "pendidikan_terakhir": pendidikan_terakhir,
        "suku": suku
    })
    db.commit()

