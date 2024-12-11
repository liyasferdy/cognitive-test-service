from fastapi import FastAPI, HTTPException, Depends, APIRouter
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from starlette.responses import JSONResponse
from sqlalchemy.exc import IntegrityError
from datetime import timedelta
import models
import jwt
from jose import JWTError
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List


# Inisialisasi FastAPI
app = FastAPI()

# Konfigurasi CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# OAuth2PasswordBearer
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# Inisialisasi Routers
auth_router = APIRouter(tags=["Authentication"])
answer_router = APIRouter(tags=["Answers"])
user_router = APIRouter(tags=["Users Data"])

# Model untuk Data Jawaban
class Answer(BaseModel):
    questionNumber: int
    selectedAnswer: str

class SubmissionData(BaseModel):
    answers: List[Answer]

# Model untuk Data Pengguna
class UserData(BaseModel):
    nama: str
    usia: int
    jenis_kelamin: str
    domisili: str
    pendidikan_terakhir: str
    suku: str


# In-memory store for answers
answers_db = []



@app.exception_handler(IntegrityError)
async def integrity_error_handler(request, exc):
    """
    Tangani error integritas database.
    """
    return JSONResponse(
        status_code=400,
        content={"detail": "Data melanggar aturan integritas database, kemungkinan duplikasi data"},
    )



# AUTH ROUTES

# Endpoint Signup
@auth_router.post("/signup")
async def signup(user: models.UserCreate, db: Session = Depends(models.get_db)):
    """
    Endpoint untuk mendaftarkan pengguna baru.
    """
    # Periksa apakah username sudah digunakan
    if models.is_username_taken(db, user.username):
        raise HTTPException(
            status_code=400, 
            detail=f"Username '{user.username}' sudah terdaftar"
        )

    # Buat pengguna baru
    try:
        user_created = models.create_user(db, user)
        return {"msg": "Pendaftaran berhasil", "username": user_created.username}
    except Exception as e:
        raise HTTPException(status_code=500, detail="Terjadi kesalahan saat mendaftarkan pengguna")


# Endpoint Login
@auth_router.post("/login")
async def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(models.get_db)):
    """
    Login pengguna dan menghasilkan JWT token.
    """
    # Ambil user berdasarkan username
    user = models.get_user_by_username(db, form_data.username)
    if not user:
        raise HTTPException(status_code=401, detail="Username atau password salah")

    # Verifikasi password
    if not models.verify_password(form_data.password, user.password):
        raise HTTPException(status_code=401, detail="Username atau password salah")

    # Generate JWT token
    access_token_expires = timedelta(minutes=models.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = models.create_access_token(
        data={"sub": form_data.username}, expires_delta=access_token_expires
    )

    # Simpan token ke dalam database
    models.save_token(db, form_data.username, access_token)

    return {"access_token": access_token, "token_type": "bearer"}



@auth_router.get("/users/me")
async def read_users_me(token: str = Depends(oauth2_scheme), db: Session = Depends(models.get_db)):
    current_user = models.get_user_from_token(token, db)
    return {"username": current_user.username}


@auth_router.post("/logout")
async def logout(token: str = Depends(oauth2_scheme), db: Session = Depends(models.get_db)):
    try:
        user = models.get_user_from_token(token, db)
        models.delete_token(db, user.username)
        return {"msg": "Logout berhasil"}
    except Exception:
        raise HTTPException(status_code=401, detail="Token tidak valid")


# ANSWER ROUTES

@answer_router.post("/submit/testMV")
async def submit_answers(submission_data: SubmissionData):
    try:
        for answer in submission_data.answers:
            answer.questionNumber += 1
        answers_db.append(submission_data.answers)
        return JSONResponse(content={"message": "Answers submitted successfully"}, status_code=200)
    except Exception as e:
        raise HTTPException(status_code=500, detail="Error saving answers")


@answer_router.get("/answers/testMV")
async def get_answers():
    if not answers_db:
        raise HTTPException(status_code=404, detail="No answers found")
    return {"answers": answers_db}


# USER DATA ROUTES

@user_router.post("/users/data")
async def create_user_data(
    user_data: UserData,
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(models.get_db)
):
    current_user = models.get_user_from_token(token, db)
    models.create_user_data(
        db,
        username=current_user.username,
        nama=user_data.nama,
        usia=user_data.usia,
        jenis_kelamin=user_data.jenis_kelamin,
        domisili=user_data.domisili,
        pendidikan_terakhir=user_data.pendidikan_terakhir,
        suku=user_data.suku
    )
    return JSONResponse(content={"message": "User data saved successfully"}, status_code=201)


@user_router.get("/users/data")
async def get_user_data(token: str = Depends(oauth2_scheme), db: Session = Depends(models.get_db)):
    current_user = models.get_user_from_token(token, db)
    user_data = models.get_user_by_user_data(db, current_user.username)
    if not user_data:
        raise HTTPException(status_code=404, detail="User data not found")
    return {
        "id": user_data.id,
        "username": user_data.username,
        "nama": user_data.nama,
        "usia": user_data.usia,
        "jenis_kelamin": user_data.jenis_kelamin,
        "domisili": user_data.domisili,
        "pendidikan_terakhir": user_data.pendidikan_terakhir,
        "suku": user_data.suku,
        "created_at": user_data.created_at
    }

# Include Routers
app.include_router(auth_router)
app.include_router(answer_router)
app.include_router(user_router)
