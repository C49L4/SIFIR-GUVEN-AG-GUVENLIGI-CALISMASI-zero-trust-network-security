from fastapi import FastAPI, HTTPException, Request, Depends
from fastapi.security import HTTPBearer
from pydantic import BaseModel
from jose import jwt, JWTError
from datetime import datetime, timedelta
import bcrypt
import logging

# Loglama Ayarları
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("ZeroTrustSystem")
log_history = []

# FastAPI ve Güvenlik Şeması (Authorize butonu için)
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

SECRET_KEY = "super-secret-key"
ALGORITHM = "HS256"

# --- MIDDLEWARE (Zero Trust Katmanı) ---
@app.middleware("http")
async def security_middleware(request: Request, call_next):
    # Loglama
    log_history.append(f"{datetime.now().strftime('%H:%M:%S')} | {request.url.path} | IP: {request.client.host}")

    # Honeypot (Tuzak)
    if request.url.path == "/admin-config.php":
        raise HTTPException(status_code=403, detail="Access denied. Alert logged.")

    # Korunan alanlar (Login, Logs ve Docs dışındakiler)
    if request.url.path in ["/admin-area", "/user-area"]:
        auth = request.headers.get("Authorization")
        if not auth or not auth.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="Unauthorized")
        
        try:
            token = auth.split(" ")[1]
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            request.state.user = payload
        except JWTError:
            raise HTTPException(status_code=401, detail="Invalid token")
            
    return await call_next(request)

# --- ENDPOINTLER ---
@app.post("/login")
def login(data: LoginRequest):
    user = users_db.get(data.username)
    if not user or not verify_password(data.password, user["password"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    token = jwt.encode({"sub": data.username, "role": user["role"]}, SECRET_KEY, algorithm=ALGORITHM)
    return {"access_token": token, "token_type": "bearer"}

@app.get("/logs")
def view_logs():
    return {"son_loglar": log_history[-20:]}

# Admin Area (Güvenlik şeması ile koruma altına alındı)
@app.get("/admin-area", dependencies=[Depends(security)])
def admin_area(request: Request):
    if getattr(request.state, "user", {}).get("role") != "admin":
        raise HTTPException(status_code=403, detail="Forbidden")
    return {"message": "Admin access granted"}