from fastapi import FastAPI, HTTPException, Request, Depends
from fastapi.security import HTTPBearer
from pydantic import BaseModel
from jose import jwt, JWTError
from datetime import datetime, timedelta
import bcrypt
import logging
import os
from dotenv import load_dotenv

# .env dosyasından gizli bilgileri yükle
load_dotenv()
SECRET_KEY = os.getenv("SECRET_KEY", "gizli-ve-cok-guclu-bir-anahtar")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 15 

# Loglama Ayarları
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("ZeroTrustSystem")
log_history = []

app = FastAPI()
security = HTTPBearer()

# --- MODELLER ---
class LoginRequest(BaseModel):
    username: str
    password: str

# --- GÜVENLİK FONKSİYONLARI ---
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password[:72].encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(plain_password[:72].encode('utf-8'), hashed_password.encode('utf-8'))

users_db = {
    "admin": {"password": hash_password("1234"), "role": "admin"},
    "user": {"password": hash_password("1234"), "role": "user"}
}

# --- MIDDLEWARE ---
@app.middleware("http")
async def security_middleware(request: Request, call_next):
    log_entry = f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | {request.url.path} | IP: {request.client.host}"
    log_history.append(log_entry)

    if request.url.path in ["/admin-config.php", "/.env", "/wp-login.php"]:
        raise HTTPException(status_code=403, detail="Honeypot tetiklendi!")

    if request.url.path in ["/admin-area", "/user-area"]:
        auth = request.headers.get("Authorization")
        if not auth or not auth.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="Token bulunamadı")
        try:
            token = auth.split(" ")[1]
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            request.state.user = payload
        except JWTError:
            raise HTTPException(status_code=401, detail="Geçersiz token")
            
    return await call_next(request)

# --- ENDPOINTLER ---
@app.get("/")
def read_root():
    return {"mesaj": "Zero Trust API sistemine hoş geldin!"}

@app.post("/login")
def login(data: LoginRequest):
    user = users_db.get(data.username)
    if not user or not verify_password(data.password, user["password"]):
        raise HTTPException(status_code=401, detail="Hatalı giriş")
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    token = jwt.encode({"sub": data.username, "role": user["role"], "exp": expire}, SECRET_KEY, algorithm=ALGORITHM)
    return {"access_token": token, "token_type": "bearer"}

@app.get("/logs")
def view_logs():
    return {"son_loglar": log_history[-20:]}

@app.get("/admin-area", dependencies=[Depends(security)])
def admin_area(request: Request):
    if getattr(request.state, "user", {}).get("role") != "admin":
        raise HTTPException(status_code=403, detail="Sadece adminler girebilir!")
    return {"message": "Admin alanı onaylandı."}

@app.get("/user-area", dependencies=[Depends(security)])
def user_area():
    return {"message": "Kullanıcı alanı onaylandı."}