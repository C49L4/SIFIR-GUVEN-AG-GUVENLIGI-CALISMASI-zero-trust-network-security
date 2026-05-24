from fastapi import FastAPI, HTTPException, Request, Depends
from fastapi.security import HTTPBearer
from pydantic import BaseModel
from jose import jwt, JWTError
from datetime import datetime, timedelta
import bcrypt
import logging
import os
from dotenv import load_dotenv

# .env dosyasından gizli bilgileri yükle (SECRET_KEY'i kodun içine yazma!)
load_dotenv()
SECRET_KEY = os.getenv("SECRET_KEY", "gizli-ve-cok-guclu-bir-anahtar")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 15 # Token süresini 15 dakikaya sabitledik

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
# Şifreleri hashleyerek veritabanında güvenli saklarız
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password[:72].encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

# Giriş anında şifreyi karşılaştırırız
def verify_password(plain_password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(plain_password[:72].encode('utf-8'), hashed_password.encode('utf-8'))

users_db = {
    "admin": {"password": hash_password("1234"), "role": "admin"},
    "user": {"password": hash_password("1234"), "role": "user"}
}

# --- MIDDLEWARE (Zero Trust Katmanı) ---
@app.middleware("http")
async def security_middleware(request: Request, call_next):
    # Her isteği logluyoruz (İzlenebilirlik)
    log_entry = f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | {request.url.path} | IP: {request.client.host}"
    log_history.append(log_entry)

    # Honeypot: Saldırganların aradığı tipik zafiyet yolları (Sıfır güven politikası)
    if request.url.path in ["/admin-config.php", "/.env", "/wp-login.php"]:
        raise HTTPException(status_code=403, detail="Honeypot tetiklendi! İzinsiz erişim denemesi loglandı.")

    # Korunan rotalar için yetkilendirme kontrolü
    if request.url.path in ["/admin-area", "/user-area"]:
        auth = request.headers.get("Authorization")
        if not auth or not auth.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="Token bulunamadı")
        
        try:
            token = auth.split(" ")[1]
            # Token doğrulama ve süre kontrolü
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            request.state.user = payload
        except JWTError:
            raise HTTPException(status_code=401, detail="Token süresi dolmuş veya geçersiz")
            
    return await call_next(request)

# --- ENDPOINTLER ---
@app.post("/login")
def login(data: LoginRequest):
    user = users_db.get(data.username)
    if not user or not verify_password(data.password, user["password"]):
        raise HTTPException(status_code=401, detail="Hatalı kullanıcı adı veya şifre")
    
    # Token'a bitiş süresi (exp) ekliyoruz
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    token = jwt.encode({"sub": data.username, "role": user["role"], "exp": expire}, SECRET_KEY, algorithm=ALGORITHM)
    
    return {"access_token": token, "token_type": "bearer", "expires_in": "15 minutes"}

@app.get("/logs")
def view_logs():
    return {"son_loglar": log_history[-20:]}

@app.get("/admin-area", dependencies=[Depends(security)])
def admin_area(request: Request):
    # Sadece rolü 'admin' olanlar girebilir
    if getattr(request.state, "user", {}).get("role") != "admin":
        raise HTTPException(status_code=403, detail="Yetersiz yetki!")
    return {"message": "Admin yetkisi onaylandı. Hoş geldiniz."}