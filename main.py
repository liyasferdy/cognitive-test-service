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
from typing import List, Dict, Optional

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
time_router = APIRouter(tags=["Time Data"])

# In-memory storage untuk jawaban

answers_mm = []
answers_ma = []
answers_mv = []
answers_ms = []
answers_mw = []
answers_gfi = []
answers_vz = []
answers_rq = []
answers_vls = []    
answers_vlsa = []
answers_rg = []
answers_a3 = []
answers_rc = []


#In-memory Time data storage
time_data_MM: List[Dict] = []


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

class AnswerMW(BaseModel):
    questionNumber: int
    selectedAnswer: str

class AnswerRQ(BaseModel):
    questionNumber: int
    selectedAnswer: str

class AnswerGFI(BaseModel):
    questionNumber: int
    selectedAnswer: str

class AnswerVZ(BaseModel):
    questionNumber: int
    selectedAnswer: str

class AnswerVLS(BaseModel):
    questionNumber: int
    selectedAnswer: str

class AnswerVLSA(BaseModel):
    questionNumber: int
    selectedAnswer: str

class AnswerRG(BaseModel):
    questionNumber: int
    selectedAnswer: str

class AnswerA3(BaseModel):
    questionNumber: int
    selectedAnswer: str

class AnswerRC(BaseModel):
    articleId: int
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
    answers: List[AnswerMW]

class SubmissionDataRQ(BaseModel):
    answers: List[AnswerRQ]

class SubmissionDataGFI(BaseModel):
    answers: List[AnswerGFI]

class SubmissionDataVZ(BaseModel):
    answers: List[AnswerVZ]

class SubmissionDataVLS(BaseModel):
    answers: List[AnswerVLS]

class SubmissionDataVLSA(BaseModel):
    answers: List[AnswerVLSA]

class SubmissionDataRG(BaseModel):
    answers: List[AnswerRG]

class SubmissionDataA3(BaseModel):
    answers: List[AnswerA3]

class SubmissionDataRC(BaseModel):
    answers: List[AnswerRC]

# Model untuk Data Pengguna
class UserData(BaseModel):
    nama: str
    usia: int
    jenis_kelamin: str
    domisili: str
    pendidikan_terakhir: str
    suku: str

# Define Pydantic models for Time Data
class TimeDataMM(BaseModel):
    article: int
    questions: int


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

@answer_router.post("/submit/testRQ")
async def submit_answers_rq(
    submission_data: SubmissionDataRQ,
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
    answers_rq.append({
        "username": current_user.username,
        "nama": user_data.nama,
        "answers": submission_data.answers,
    })

    return JSONResponse(
        content={"message": "RQ answers stored successfully in memory."},
        status_code=200,
    )

@answer_router.post("/submit/testGFI")
async def submit_answers_gfi(
    submission_data: SubmissionDataGFI,
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
    answers_gfi.append({
        "username": current_user.username,
        "nama": user_data.nama,
        "answers": submission_data.answers,
    })

    return JSONResponse(
        content={"message": "GFI answers stored successfully in memory."},
        status_code=200,
    )

@answer_router.post("/submit/testVZ")
async def submit_answers_vz(
    submission_data: SubmissionDataVZ,
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
    answers_vz.append({
        "username": current_user.username,
        "nama": user_data.nama,
        "answers": submission_data.answers,
    })

    return JSONResponse(
        content={"message": "VZ answers stored successfully in memory."},
        status_code=200,
    )

@answer_router.post("/submit/testVLS")
async def submit_answers_vls(
    submission_data: SubmissionDataVLS,
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
    answers_vls.append({
        "username": current_user.username,
        "nama": user_data.nama,
        "answers": submission_data.answers,
    })

    return JSONResponse(
        content={"message": "VL-S answers stored successfully in memory."},
        status_code=200,
    )
@answer_router.post("/submit/testVLSA")
async def submit_answers_vlsa(
    submission_data: SubmissionDataVLSA,
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
    answers_vlsa.append({
        "username": current_user.username,
        "nama": user_data.nama,
        "answers": submission_data.answers,
    })

    return JSONResponse(
        content={"message": "VL-SA answers stored successfully in memory."},
        status_code=200,
    )

@answer_router.post("/submit/testRG")
async def submit_answers_rg(
    submission_data: SubmissionDataRG,
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
    answers_rg.append({
        "username": current_user.username,
        "nama": user_data.nama,
        "answers": submission_data.answers,
    })

    return JSONResponse(
        content={"message": "RG answers stored successfully in memory."},
        status_code=200,
    )

@answer_router.post("/submit/testA3")
async def submit_answers_a3(
    submission_data: SubmissionDataA3,
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
    answers_a3.append({
        "username": current_user.username,
        "nama": user_data.nama,
        "answers": submission_data.answers,
    })

    return JSONResponse(
        content={"message": "A3 answers stored successfully in memory."},
        status_code=200,
    )

@answer_router.post("/submit/testRC")
async def submit_answers_rc(
    submission_data: SubmissionDataRC,
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
    answers_rc.append({
        "username": current_user.username,
        "nama": user_data.nama,
        "answers": submission_data.answers,
    })

    return JSONResponse(
        content={"message": "RC answers stored successfully in memory."},
        status_code=200,
    )

@answer_router.post("/answers/savetoDB")
async def save_combined_answers_to_db(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(models.get_db)
):
    """
    Save all combined test answers from in-memory storage to the database.
    """
    # Get the current user from the token
    current_user = models.get_user_from_token(token, db)

    try:
        # Check if in-memory storage contains answers for any test
        if not any([answers_mm, answers_ma, answers_mv, answers_ms, answers_mw, answers_rq, answers_gfi, answers_vz, answers_vls, answers_vlsa, answers_rg, answers_a3, answers_rc]):
            raise HTTPException(status_code=400, detail="No answers found in memory to save.")

        # # Log the memory contents for debugging (optional)
        # print("MM answers in memory:", answers_mm)
        # print("MA answers in memory:", answers_ma)
        # print("MV answers in memory:", answers_mv)
        # print("MS answers in memory:", answers_ms)
        # print("MW answers in memory:", answers_mw)
        # print("RQ answers in memory:", answers_rq)
        # print("GFI answers in memory:", answers_gfi)
        # print("VZ answers in memory:", answers_vz)
        # print("VLS answers in memory:", answers_vls)
        # print("VLSA answers in memory:", answers_vlsa)
        # print("RG answers in memory:", answers_rg)
        # print("A3 answers in memory:", answers_a3)
        # print("RC answers in memory:", answers_rc)

        # Extract username and name from the first non-empty memory storage
        username = (
            answers_mm[0]["username"]
            if answers_mm else (answers_ma[0]["username"] if answers_ma else
            (answers_mv[0]["username"] if answers_mv else
            (answers_ms[0]["username"] if answers_ms else
            (answers_mw[0]["username"] if answers_mw else
            (answers_rq[0]["username"] if answers_rq else
            (answers_gfi[0]["username"] if answers_gfi else
            (answers_vz[0]["username"] if answers_vz else
            (answers_vls[0]["username"] if answers_vls else
            (answers_vlsa[0]["username"] if answers_vlsa else
            (answers_rg[0]["username"] if answers_rg else
            (answers_a3[0]["username"] if answers_a3 else
            answers_rc[0]["username"]))))))))))))
    
        nama = (
            answers_mm[0]["nama"]
            if answers_mm else (answers_ma[0]["nama"] if answers_ma else
            (answers_mv[0]["nama"] if answers_mv else
            (answers_ms[0]["nama"] if answers_ms else
            (answers_mw[0]["nama"] if answers_mw else
            (answers_rq[0]["nama"] if answers_rq else
            (answers_gfi[0]["nama"] if answers_gfi else
            (answers_vz[0]["nama"] if answers_vz else
            (answers_vls[0]["nama"] if answers_vls else
            (answers_vlsa[0]["nama"] if answers_vlsa else
            (answers_rg[0]["nama"] if answers_rg else
            (answers_a3[0]["nama"] if answers_a3 else
            answers_rc[0]["nama"]))))))))))))

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

        combined_answersRQ = [
            answer.dict() for item in answers_rq for answer in item["answers"]
        ] if answers_rq else []

        combined_answersGFI = [
            answer.dict() for item in answers_gfi for answer in item["answers"]
        ] if answers_gfi else []

        combined_answersVZ = [
            answer.dict() for item in answers_vz for answer in item["answers"]
        ] if answers_vz else []

        combined_answersVLS = [
            answer.dict() for item in answers_vls for answer in item["answers"]
        ] if answers_vls else []

        combined_answersVLSA = [
            answer.dict() for item in answers_vlsa for answer in item["answers"]
        ] if answers_vlsa else []

        combined_answersRG = [
            answer.dict() for item in answers_rg for answer in item["answers"]
        ] if answers_rg else []

        combined_answersA3 = [
            answer.dict() for item in answers_a3 for answer in item["answers"]
        ] if answers_a3 else []

        combined_answersRC = [
            answer.dict() for item in answers_rc for answer in item["answers"]
        ] if answers_rc else []

        # Create a new entry for the database
        new_test_entry = models.TestDB(
            username=username,
            nama=nama,
            answers_mm=combined_answersMM,
            answers_ma=combined_answersMA,
            answers_mv=combined_answersMV,
            answers_ms=combined_answersMS,
            answers_mw=combined_answersMW,
            answers_rq=combined_answersRQ,
            answers_gfi=combined_answersGFI,
            answers_vz=combined_answersVZ,
            answers_vls=combined_answersVLS,  # Include VLS test answers
            answers_vlsa=combined_answersVLSA,  # Include VLSA test answers
            answers_rg=combined_answersRG,  # Include RG test answers
            answers_a3=combined_answersA3,  # Include A3 test answers
            answers_rc=combined_answersRC  # Include RC test answers
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
        answers_rq.clear()
        answers_gfi.clear()
        answers_vz.clear()
        answers_vls.clear()
        answers_vlsa.clear()
        answers_rg.clear()
        answers_a3.clear()
        answers_rc.clear()

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
async def get_answers_mm(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(models.get_db)
):
    """
    Get MM answers for the current user from in-memory storage.
    """
    current_user = models.get_user_from_token(token, db)
    
    # Filter answers for the current user
    user_answers = [answer for answer in answers_mm if answer["username"] == current_user.username]
    
    if not user_answers:
        raise HTTPException(status_code=404, detail="No MM answers found for the current user.")
    
    return {"answersMM": user_answers}


@answer_router.get("/answers/testMA")
async def get_answers_ma(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(models.get_db)
):
    """
    Get MA answers for the current user from in-memory storage.
    """
    current_user = models.get_user_from_token(token, db)
    
    # Filter answers for the current user
    user_answers = [answer for answer in answers_ma if answer["username"] == current_user.username]
    
    if not user_answers:
        raise HTTPException(status_code=404, detail="No MA answers found for the current user.")
    
    return {"answersMA": user_answers}

@answer_router.get("/answers/testMV")
async def get_answers_mv(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(models.get_db)
):
    """
    Get MV answers for the current user from in-memory storage.
    """
    current_user = models.get_user_from_token(token, db)
    
    # Filter answers for the current user
    user_answers = [answer for answer in answers_mv if answer["username"] == current_user.username]
    
    if not user_answers:
        raise HTTPException(status_code=404, detail="No MV answers found for the current user.")
    
    return {"answersMV": user_answers}

@answer_router.get("/answers/testMS")
async def get_answers_ms(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(models.get_db)
):
    """
    Get MS answers for the current user from in-memory storage.
    """
    current_user = models.get_user_from_token(token, db)
    
    # Filter answers for the current user
    user_answers = [answer for answer in answers_ms if answer["username"] == current_user.username]
    
    if not user_answers:
        raise HTTPException(status_code=404, detail="No MS answers found for the current user.")
    
    return {"answersMS": user_answers}

@answer_router.get("/answers/testMW")
async def get_answers_mw(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(models.get_db)
):
    """
    Get MW answers for the current user from in-memory storage.
    """
    current_user = models.get_user_from_token(token, db)
    
    # Filter answers for the current user
    user_answers = [answer for answer in answers_mw if answer["username"] == current_user.username]
    
    if not user_answers:
        raise HTTPException(status_code=404, detail="No MW answers found for the current user.")
    
    return {"answersMW": user_answers}


@answer_router.get("/answers/testRQ")
async def get_answers_rq(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(models.get_db)
):
    """
    Get MA answers for the current user from in-memory storage.
    """
    current_user = models.get_user_from_token(token, db)
    
    # Filter answers for the current user
    user_answers = [answer for answer in answers_rq if answer["username"] == current_user.username]
    
    if not user_answers:
        raise HTTPException(status_code=404, detail="No RQ answers found for the current user.")
    
    return {"answersRQ": user_answers}

@answer_router.get("/answers/testGFI")
async def get_answers_gfi(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(models.get_db)
):
    """
    Get GFI answers for the current user from in-memory storage.
    """
    current_user = models.get_user_from_token(token, db)
    
    # Filter answers for the current user
    user_answers = [answer for answer in answers_gfi if answer["username"] == current_user.username]
    
    if not user_answers:
        raise HTTPException(status_code=404, detail="No GFI answers found for the current user.")
    
    return {"answersGFI": user_answers}


@answer_router.get("/answers/testVZ")
async def get_answers_vz(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(models.get_db)
):
    """
    Get VZ answers for the current user from in-memory storage.
    """
    current_user = models.get_user_from_token(token, db)
    
    # Filter answers for the current user
    user_answers = [answer for answer in answers_vz if answer["username"] == current_user.username]
    
    if not user_answers:
        raise HTTPException(status_code=404, detail="No VZ answers found for the current user.")
    
    return {"answersVZ": user_answers}

@answer_router.get("/answers/testVLS")
async def get_answers_vls(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(models.get_db)
):
    """
    Get VLS answers for the current user from in-memory storage.
    """
    current_user = models.get_user_from_token(token, db)
    
    # Filter answers for the current user
    user_answers = [answer for answer in answers_vls if answer["username"] == current_user.username]
    
    if not user_answers:
        raise HTTPException(status_code=404, detail="No VLS answers found for the current user.")
    
    return {"answersVLS": user_answers}

@answer_router.get("/answers/testVLSA")
async def get_answers_vla(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(models.get_db)
):
    """
    Get VLSAanswers for the current user from in-memory storage.
    """
    current_user = models.get_user_from_token(token, db)
    
    # Filter answers for the current user
    user_answers = [answer for answer in answers_vlsa if answer["username"] == current_user.username]
    
    if not user_answers:
        raise HTTPException(status_code=404, detail="No VLSA answers found for the current user.")
    
    return {"answersVLSA": user_answers}

@answer_router.get("/answers/testRG")
async def get_answers_rg(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(models.get_db)
):
    """
    Get RG answers for the current user from in-memory storage.
    """
    current_user = models.get_user_from_token(token, db)
    
    # Filter answers for the current user
    user_answers = [answer for answer in answers_rg if answer["username"] == current_user.username]
    
    if not user_answers:
        raise HTTPException(status_code=404, detail="No RG answers found for the current user.")
    
    return {"answersRG": user_answers}

@answer_router.get("/answers/testA3")
async def get_answers_a3(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(models.get_db)
):
    """
    Get A3 answers for the current user from in-memory storage.
    """
    current_user = models.get_user_from_token(token, db)
    
    # Filter answers for the current user
    user_answers = [answer for answer in answers_a3 if answer["username"] == current_user.username]
    
    if not user_answers:
        raise HTTPException(status_code=404, detail="No A3 answers found for the current user.")
    
    return {"answersA3": user_answers}

@answer_router.get("/answers/testRC")
async def get_answers_rc(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(models.get_db)
):
    """
    Get RC answers for the current user from in-memory storage.
    """
    current_user = models.get_user_from_token(token, db)
    
    # Filter answers for the current user
    user_answers = [answer for answer in answers_rc if answer["username"] == current_user.username]
    
    if not user_answers:
        raise HTTPException(status_code=404, detail="No RC answers found for the current user.")
    
    return {"answersRC": user_answers}



#TIME ROUTES
# Endpoint to save or update time for a user
@time_router.post("/time/testMM")
async def submit_answers_mm(
    time_data: TimeDataMM,
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(models.get_db)
):
    """
    Save or update time data for a user in-memory.
    """
    current_user = models.get_user_from_token(token, db)
    if not current_user:
        raise HTTPException(status_code=403, detail="Invalid token or user not found")

    # Find existing user data
    existing_entry = next((entry for entry in time_data_MM if entry["username"] == current_user.username), None)

    # Update if exists, otherwise add new entry
    if existing_entry:
        existing_entry["time_data"] = {
            "article": time_data.article,
            "questions": time_data.questions,
        }
    else:
        time_data_MM.append({
            "username": current_user.username,
            "time_data": {
                "article": time_data.article,
                "questions": time_data.questions,
            }
        })

    return JSONResponse(
        content={"message": "Time data stored successfully."},
        status_code=200,
    )


# Endpoint to retrieve time data
@time_router.get("/time/testMM")
async def get_time_mm(
    token: str = Depends(oauth2_scheme),
    username: Optional[str] = None,
    db: Session = Depends(models.get_db)
):
    """
    Retrieve time data for a specific user or all users.
    """
    current_user = models.get_user_from_token(token, db)
    if not current_user:
        raise HTTPException(status_code=403, detail="Invalid token or user not found")

    # If a specific username is provided, retrieve only their data
    if username:
        if current_user.username != username:
            raise HTTPException(status_code=403, detail="Unauthorized access")

        user_data = next((entry for entry in time_data_MM if entry["username"] == username), None)
        if not user_data:
            raise HTTPException(status_code=404, detail="User data not found")

        return {
            "username": username,
            "time_data": user_data["time_data"]
        }

    # If no username is provided, retrieve all data
    if not time_data_MM:
        raise HTTPException(status_code=404, detail="No time data found.")

    return {"time_data_MM": time_data_MM}





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
app.include_router(time_router)
