from fastapi import FastAPI, HTTPException, Depends, APIRouter
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from datetime import timedelta
import models
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

# In-memory storage untuk jawaban
answers_mv = []
answers_ma = []
answers_mm = []
answers_ms = []
answers_mw = []


# Model untuk Data Jawaban
class AnswerMM(BaseModel):
    articleId: int
    questionNumber: int
    selectedAnswer: str

class AnswerMA(BaseModel):
    questionNumber: int
    selectedAnswer: str

class AnswerMV(BaseModel):
    questionNumber: int
    selectedAnswer: str

class AnswerMS(BaseModel):
    questionNumber: int
    selectedAnswer: str

class SubmissionDataMM(BaseModel):
    answers: List[AnswerMM]

class SubmissionDataMA(BaseModel):
    answers: List[AnswerMA]

class SubmissionDataMV(BaseModel):
    answers: List[AnswerMV]
    
class SubmissionDataMS(BaseModel):
    answers: List[AnswerMS]

class SubmissionDataMW(BaseModel):
    answers: List[AnswerMS]

# Model untuk Data Pengguna
class UserData(BaseModel):
    nama: str
    usia: int
    jenis_kelamin: str
    domisili: str
    pendidikan_terakhir: str
    suku: str


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
@auth_router.post("/signup")
async def signup(user: models.UserCreate, db: Session = Depends(models.get_db)):
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


@auth_router.post("/login")
async def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(models.get_db)):
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


# Answer Routes

@answer_router.post("/submit/testMM")
async def submit_answers_mm(
    submission_data: SubmissionDataMM,
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(models.get_db)
):
    """
    Save Meaningful Memory (MM) test answers to in-memory storage.
    """
    current_user = models.get_user_from_token(token, db)
    user_data = models.get_user_by_user_data(db, current_user.username)
    if not user_data:
        raise HTTPException(status_code=404, detail="User data not found")

    # Save answers to in-memory storage
    answers_mm.append({
        "username": current_user.username,
        "nama": user_data.nama,
        "answers": submission_data.answers,
    })

    return JSONResponse(
        content={"message": "MM answers stored successfully in memory."},
        status_code=200,
    )


@answer_router.post("/submit/testMA")
async def submit_answers_ma(
    submission_data: SubmissionDataMA,
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(models.get_db)
):
    """
    Save Mental Visualization (MV) test answers to in-memory storage.
    """
    current_user = models.get_user_from_token(token, db)
    user_data = models.get_user_by_user_data(db, current_user.username)
    if not user_data:
        raise HTTPException(status_code=404, detail="User data not found")

    # Save answers to in-memory storage
    answers_ma.append({
        "username": current_user.username,
        "nama": user_data.nama,
        "answers": submission_data.answers,
    })

    return JSONResponse(
        content={"message": "MA answers stored successfully in memory."},
        status_code=200,
    )

@answer_router.post("/submit/testMV")
async def submit_answers_mv(
    submission_data: SubmissionDataMV,
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(models.get_db)
):
    """
    Save Mental Visualization (MV) test answers to in-memory storage.
    """
    current_user = models.get_user_from_token(token, db)
    user_data = models.get_user_by_user_data(db, current_user.username)
    if not user_data:
        raise HTTPException(status_code=404, detail="User data not found")

    # Save answers to in-memory storage
    answers_mv.append({
        "username": current_user.username,
        "nama": user_data.nama,
        "answers": submission_data.answers,
    })

    return JSONResponse(
        content={"message": "MV answers stored successfully in memory."},
        status_code=200,
    )

@answer_router.post("/submit/testMS")
async def submit_answers_ms(
    submission_data: SubmissionDataMS,
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(models.get_db)
):
    """
    Save Mental Visualization (MV) test answers to in-memory storage.
    """
    current_user = models.get_user_from_token(token, db)
    user_data = models.get_user_by_user_data(db, current_user.username)
    if not user_data:
        raise HTTPException(status_code=404, detail="User data not found")

    # Save answers to in-memory storage
    answers_ms.append({
        "username": current_user.username,
        "nama": user_data.nama,
        "answers": submission_data.answers,
    })

    return JSONResponse(
        content={"message": "MS answers stored successfully in memory."},
        status_code=200,
    )

@answer_router.post("/submit/testMW")
async def submit_answers_mw(
    submission_data: SubmissionDataMS,
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(models.get_db)
):
    """
    Save Mental Visualization (MV) test answers to in-memory storage.
    """
    current_user = models.get_user_from_token(token, db)
    user_data = models.get_user_by_user_data(db, current_user.username)
    if not user_data:
        raise HTTPException(status_code=404, detail="User data not found")

    # Save answers to in-memory storage
    answers_mw.append({
        "username": current_user.username,
        "nama": user_data.nama,
        "answers": submission_data.answers,
    })

    return JSONResponse(
        content={"message": "MW answers stored successfully in memory."},
        status_code=200,
    )

@answer_router.post("/answers/savetoDB")
async def save_combined_answers_to_db(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(models.get_db)
):
    """
    Save all combined test answers (MM, MA, MV, MS, MW) from in-memory storage to the database.
    """
    # Get the current user from the token
    current_user = models.get_user_from_token(token, db)

    try:
        # Check if in-memory storage contains answers for any test
        if not any([answers_mm, answers_ma, answers_mv, answers_ms, answers_mw]):
            raise HTTPException(status_code=400, detail="No answers found in memory to save.")

        # Log the memory contents for debugging (optional)
        print("MM answers in memory:", answers_mm)
        print("MA answers in memory:", answers_ma)
        print("MV answers in memory:", answers_mv)
        print("MS answers in memory:", answers_ms)
        print("MW answers in memory:", answers_mw)

        # Extract username and name from the first non-empty memory storage
        username = (
            answers_mm[0]["username"]
            if answers_mm else (answers_ma[0]["username"] if answers_ma else
            (answers_mv[0]["username"] if answers_mv else
            (answers_ms[0]["username"] if answers_ms else answers_mw[0]["username"])))
        )
        nama = (
            answers_mm[0]["nama"]
            if answers_mm else (answers_ma[0]["nama"] if answers_ma else
            (answers_mv[0]["nama"] if answers_mv else
            (answers_ms[0]["nama"] if answers_ms else answers_mw[0]["nama"])))
        )

        # Prepare combined answers from each test's storage
        combined_answersMM = [
            answer.dict() for item in answers_mm for answer in item["answers"]
        ] if answers_mm else []

        combined_answersMA = [
            answer.dict() for item in answers_ma for answer in item["answers"]
        ] if answers_ma else []

        combined_answersMV = [
            answer.dict() for item in answers_mv for answer in item["answers"]
        ] if answers_mv else []

        combined_answersMS = [
            answer.dict() for item in answers_ms for answer in item["answers"]
        ] if answers_ms else []

        combined_answersMW = [
            answer.dict() for item in answers_mw for answer in item["answers"]
        ] if answers_mw else []

        # Create a new entry for the database
        new_test_entry = models.TestDB(
            username=username,
            nama=nama,
            answers_mm=combined_answersMM,
            answers_ma=combined_answersMA,
            answers_mv=combined_answersMV,
            answers_ms=combined_answersMS,
            answers_mw=combined_answersMW  # Include MW test answers now
        )

        # Add and commit the new entry to the database
        db.add(new_test_entry)
        db.commit()
        db.refresh(new_test_entry)

        # Clear in-memory storage after successful save
        answers_mm.clear()
        answers_ma.clear()
        answers_mv.clear()
        answers_ms.clear()
        answers_mw.clear()

        return JSONResponse(
            content={"message": "All answers have been saved to the database successfully."},
            status_code=200
        )

    except Exception as e:
        # Rollback any database changes in case of an error
        db.rollback()
        print("Error during saving answers to DB:", str(e))  # Log the error
        raise HTTPException(
            status_code=500,
            detail=f"Error saving answers to the database: {str(e)}"
        )



@answer_router.get("/answers/testMM")
async def get_answers_mm():
    """
    Get all MM answers from in-memory storage.
    """
    if not answers_mm:
        raise HTTPException(status_code=404, detail="No MM answers found.")
    return {"answersMM": answers_mm}

@answer_router.get("/answers/testMA")
async def get_answers_ma():
    """
    Get all MV answers from in-memory storage.
    """
    if not answers_ma:
        raise HTTPException(status_code=404, detail="No MA answers found.")
    return {"answersMA": answers_ma}

@answer_router.get("/answers/testMV")
async def get_answers_mv():
    """
    Get all MV answers from in-memory storage.
    """
    if not answers_mv:
        raise HTTPException(status_code=404, detail="No MV answers found.")
    return {"answersMV": answers_mv}

@answer_router.get("/answers/testMS")
async def get_answers_ms():
    """
    Get all MV answers from in-memory storage.
    """
    if not answers_ms:
        raise HTTPException(status_code=404, detail="No MS answers found.")
    return {"answersMV": answers_ms}

@answer_router.get("/answers/testMW")
async def get_answers_mw():
    """
    Get all MV answers from in-memory storage.
    """
    if not answers_mw:
        raise HTTPException(status_code=404, detail="No MS answers found.")
    return {"answersMV": answers_mw}

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
app.include_router(user_router)
app.include_router(answer_router)
