# backend/main.py
import os
from datetime import datetime, timedelta
from typing import List, Optional

import jwt
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.context import CryptContext
from pydantic import BaseModel
from sqlalchemy import Column, DateTime, Integer, String, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import Session, sessionmaker

from elasticsearch import Elasticsearch

# Initialize Elasticsearch client
ELASTICSEARCH_URL = os.getenv("ELASTICSEARCH_URL", "http://elasticsearch:9200")
es_client = Elasticsearch([ELASTICSEARCH_URL])

# Add a new endpoint to fetch real data from Elasticsearch
@app.get("/es-security-events")
async def get_es_security_events(
    current_user: User = Depends(get_current_user),
    index: str = "filebeat-*",
    size: int = 100
):
    query = {
        "query": {
            "match_all": {}
        },
        "sort": [
            {"@timestamp": {"order": "desc"}}
        ],
        "size": size
    }
    
    response = es_client.search(index=index, body=query)
    return response["hits"]["hits"]

# Database configuration
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://user:password@db:5432/siem_db")
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Security configuration
SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-for-jwt")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Models
class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    
class SecurityEvent(Base):
    __tablename__ = "security_events"
    
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    event_type = Column(String, index=True)
    source_ip = Column(String)
    destination_ip = Column(String)
    severity = Column(String)
    description = Column(String)

# Pydantic models
class UserBase(BaseModel):
    username: str
    
class UserCreate(UserBase):
    password: str
    
class UserInDB(UserBase):
    id: int
    hashed_password: str
    
    class Config:
        orm_mode = True
        
class User(UserBase):
    id: int
    
    class Config:
        orm_mode = True
        
class Token(BaseModel):
    access_token: str
    token_type: str
    
class TokenData(BaseModel):
    username: Optional[str] = None
    
class SecurityEventBase(BaseModel):
    event_type: str
    source_ip: str
    destination_ip: str
    severity: str
    description: str
    
class SecurityEventCreate(SecurityEventBase):
    pass
    
class SecurityEvent(SecurityEventBase):
    id: int
    timestamp: datetime
    
    class Config:
        orm_mode = True

# Database Dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Security functions
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def get_user(db: Session, username: str):
    return db.query(User).filter(User.username == username).first()

def authenticate_user(db: Session, username: str, password: str):
    user = get_user(db, username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except jwt.PyJWTError:
        raise credentials_exception
    user = get_user(db, username=token_data.username)
    if user is None:
        raise credentials_exception
    return user

# FastAPI App
app = FastAPI(title="SIEM Dashboard API")

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # For development only, restrict in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize database
@app.on_event("startup")
async def startup():
    Base.metadata.create_all(bind=engine)
    
    # Add a default user if none exists
    db = SessionLocal()
    if db.query(User).count() == 0:
        default_user = User(username="admin", hashed_password=get_password_hash("password"))
        db.add(default_user)
        db.commit()
    
    # Add some mock security events if none exist
    if db.query(SecurityEvent).count() == 0:
        mock_events = [
            SecurityEvent(
                event_type="Brute Force Attack",
                source_ip="192.168.1.100",
                destination_ip="10.0.0.5",
                severity="High",
                description="Multiple failed login attempts detected",
                timestamp=datetime.utcnow() - timedelta(hours=2)
            ),
            SecurityEvent(
                event_type="SQL Injection Attempt",
                source_ip="192.168.1.101",
                destination_ip="10.0.0.6",
                severity="Critical",
                description="SQL injection pattern detected in web request",
                timestamp=datetime.utcnow() - timedelta(hours=1)
            ),
            SecurityEvent(
                event_type="Malware Detection",
                source_ip="192.168.1.103",
                destination_ip="10.0.0.7",
                severity="Medium",
                description="Potential malware signature detected in network traffic",
                timestamp=datetime.utcnow() - timedelta(minutes=30)
            ),
            SecurityEvent(
                event_type="Suspicious File Access",
                source_ip="192.168.1.104",
                destination_ip="10.0.0.8",
                severity="Low",
                description="Unusual file access pattern detected",
                timestamp=datetime.utcnow() - timedelta(minutes=15)
            ),
            SecurityEvent(
                event_type="Unauthorized Access",
                source_ip="192.168.1.105",
                destination_ip="10.0.0.9",
                severity="High",
                description="Unauthorized access to restricted system resource",
                timestamp=datetime.utcnow() - timedelta(minutes=5)
            ),
        ]
        db.add_all(mock_events)
        db.commit()
    db.close()

# Authentication
@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/users/me", response_model=User)
async def read_users_me(current_user: User = Depends(get_current_user)):
    return current_user

# Security Events API
@app.get("/security-events", response_model=List[SecurityEvent])
async def get_security_events(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    skip: int = 0,
    limit: int = 100
):
    events = db.query(SecurityEvent).order_by(SecurityEvent.timestamp.desc()).offset(skip).limit(limit).all()
    return events

# Health check endpoint
@app.get("/health")
async def health_check():
    return {"status": "ok"}1~# backend/main.py
import os
from datetime import datetime, timedelta
from typing import List, Optional

import jwt
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.context import CryptContext
from pydantic import BaseModel
from sqlalchemy import Column, DateTime, Integer, String, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import Session, sessionmaker

# Database configuration
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://user:password@db:5432/siem_db")
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Security configuration
SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-for-jwt")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Models
class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    
class SecurityEvent(Base):
    __tablename__ = "security_events"
    
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    event_type = Column(String, index=True)
    source_ip = Column(String)
    destination_ip = Column(String)
    severity = Column(String)
    description = Column(String)

# Pydantic models
class UserBase(BaseModel):
    username: str
    
class UserCreate(UserBase):
    password: str
    
class UserInDB(UserBase):
    id: int
    hashed_password: str
    
    class Config:
        orm_mode = True
        
class User(UserBase):
    id: int
    
    class Config:
        orm_mode = True
        
class Token(BaseModel):
    access_token: str
    token_type: str
    
class TokenData(BaseModel):
    username: Optional[str] = None
    
class SecurityEventBase(BaseModel):
    event_type: str
    source_ip: str
    destination_ip: str
    severity: str
    description: str
    
class SecurityEventCreate(SecurityEventBase):
    pass
    
class SecurityEvent(SecurityEventBase):
    id: int
    timestamp: datetime
    
    class Config:
        orm_mode = True

# Database Dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Security functions
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def get_user(db: Session, username: str):
    return db.query(User).filter(User.username == username).first()

def authenticate_user(db: Session, username: str, password: str):
    user = get_user(db, username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except jwt.PyJWTError:
        raise credentials_exception
    user = get_user(db, username=token_data.username)
    if user is None:
        raise credentials_exception
    return user

# FastAPI App
app = FastAPI(title="SIEM Dashboard API")

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # For development only, restrict in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize database
@app.on_event("startup")
async def startup():
    Base.metadata.create_all(bind=engine)
    
    # Add a default user if none exists
    db = SessionLocal()
    if db.query(User).count() == 0:
        default_user = User(username="admin", hashed_password=get_password_hash("password"))
        db.add(default_user)
        db.commit()
    
    # Add some mock security events if none exist
    if db.query(SecurityEvent).count() == 0:
        mock_events = [
            SecurityEvent(
                event_type="Brute Force Attack",
                source_ip="192.168.1.100",
                destination_ip="10.0.0.5",
                severity="High",
                description="Multiple failed login attempts detected",
                timestamp=datetime.utcnow() - timedelta(hours=2)
            ),
            SecurityEvent(
                event_type="SQL Injection Attempt",
                source_ip="192.168.1.101",
                destination_ip="10.0.0.6",
                severity="Critical",
                description="SQL injection pattern detected in web request",
                timestamp=datetime.utcnow() - timedelta(hours=1)
            ),
            SecurityEvent(
                event_type="Malware Detection",
                source_ip="192.168.1.103",
                destination_ip="10.0.0.7",
                severity="Medium",
                description="Potential malware signature detected in network traffic",
                timestamp=datetime.utcnow() - timedelta(minutes=30)
            ),
            SecurityEvent(
                event_type="Suspicious File Access",
                source_ip="192.168.1.104",
                destination_ip="10.0.0.8",
                severity="Low",
                description="Unusual file access pattern detected",
                timestamp=datetime.utcnow() - timedelta(minutes=15)
            ),
            SecurityEvent(
                event_type="Unauthorized Access",
                source_ip="192.168.1.105",
                destination_ip="10.0.0.9",
                severity="High",
                description="Unauthorized access to restricted system resource",
                timestamp=datetime.utcnow() - timedelta(minutes=5)
            ),
        ]
        db.add_all(mock_events)
        db.commit()
    db.close()

# Authentication
@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/users/me", response_model=User)
async def read_users_me(current_user: User = Depends(get_current_user)):
    return current_user

# Security Events API
@app.get("/security-events", response_model=List[SecurityEvent])
async def get_security_events(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    skip: int = 0,
    limit: int = 100
):
    events = db.query(SecurityEvent).order_by(SecurityEvent.timestamp.desc()).offset(skip).limit(limit).all()
    return events

# Health check endpoint
@app.get("/health")
async def health_check():
    return {"status": "ok"}1~# backend/main.py
import os
from datetime import datetime, timedelta
from typing import List, Optional

import jwt
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.context import CryptContext
from pydantic import BaseModel
from sqlalchemy import Column, DateTime, Integer, String, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import Session, sessionmaker

# Database configuration
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://user:password@db:5432/siem_db")
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Security configuration
SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-for-jwt")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Models
class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    
class SecurityEvent(Base):
    __tablename__ = "security_events"
    
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    event_type = Column(String, index=True)
    source_ip = Column(String)
    destination_ip = Column(String)
    severity = Column(String)
    description = Column(String)

# Pydantic models
class UserBase(BaseModel):
    username: str
    
class UserCreate(UserBase):
    password: str
    
class UserInDB(UserBase):
    id: int
    hashed_password: str
    
    class Config:
        orm_mode = True
        
class User(UserBase):
    id: int
    
    class Config:
        orm_mode = True
        
class Token(BaseModel):
    access_token: str
    token_type: str
    
class TokenData(BaseModel):
    username: Optional[str] = None
    
class SecurityEventBase(BaseModel):
    event_type: str
    source_ip: str
    destination_ip: str
    severity: str
    description: str
    
class SecurityEventCreate(SecurityEventBase):
    pass
    
class SecurityEvent(SecurityEventBase):
    id: int
    timestamp: datetime
    
    class Config:
        orm_mode = True

# Database Dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Security functions
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def get_user(db: Session, username: str):
    return db.query(User).filter(User.username == username).first()

def authenticate_user(db: Session, username: str, password: str):
    user = get_user(db, username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except jwt.PyJWTError:
        raise credentials_exception
    user = get_user(db, username=token_data.username)
    if user is None:
        raise credentials_exception
    return user

# FastAPI App
app = FastAPI(title="SIEM Dashboard API")

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # For development only, restrict in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize database
@app.on_event("startup")
async def startup():
    Base.metadata.create_all(bind=engine)
    
    # Add a default user if none exists
    db = SessionLocal()
    if db.query(User).count() == 0:
        default_user = User(username="admin", hashed_password=get_password_hash("password"))
        db.add(default_user)
        db.commit()
    
    # Add some mock security events if none exist
    if db.query(SecurityEvent).count() == 0:
        mock_events = [
            SecurityEvent(
                event_type="Brute Force Attack",
                source_ip="192.168.1.100",
                destination_ip="10.0.0.5",
                severity="High",
                description="Multiple failed login attempts detected",
                timestamp=datetime.utcnow() - timedelta(hours=2)
            ),
            SecurityEvent(
                event_type="SQL Injection Attempt",
                source_ip="192.168.1.101",
                destination_ip="10.0.0.6",
                severity="Critical",
                description="SQL injection pattern detected in web request",
                timestamp=datetime.utcnow() - timedelta(hours=1)
            ),
            SecurityEvent(
                event_type="Malware Detection",
                source_ip="192.168.1.103",
                destination_ip="10.0.0.7",
                severity="Medium",
                description="Potential malware signature detected in network traffic",
                timestamp=datetime.utcnow() - timedelta(minutes=30)
            ),
            SecurityEvent(
                event_type="Suspicious File Access",
                source_ip="192.168.1.104",
                destination_ip="10.0.0.8",
                severity="Low",
                description="Unusual file access pattern detected",
                timestamp=datetime.utcnow() - timedelta(minutes=15)
            ),
            SecurityEvent(
                event_type="Unauthorized Access",
                source_ip="192.168.1.105",
                destination_ip="10.0.0.9",
                severity="High",
                description="Unauthorized access to restricted system resource",
                timestamp=datetime.utcnow() - timedelta(minutes=5)
            ),
        ]
        db.add_all(mock_events)
        db.commit()
    db.close()

# Authentication
@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/users/me", response_model=User)
async def read_users_me(current_user: User = Depends(get_current_user)):
    return current_user

# Security Events API
@app.get("/security-events", response_model=List[SecurityEvent])
async def get_security_events(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    skip: int = 0,
    limit: int = 100
):
    events = db.query(SecurityEvent).order_by(SecurityEvent.timestamp.desc()).offset(skip).limit(limit).all()
    return events

# Health check endpoint
@app.get("/health")
async def health_check():
    return {"status": "ok"}1~# backend/main.py
import os
from datetime import datetime, timedelta
from typing import List, Optional

import jwt
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.context import CryptContext
from pydantic import BaseModel
from sqlalchemy import Column, DateTime, Integer, String, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import Session, sessionmaker

# Database configuration
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://user:password@db:5432/siem_db")
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Security configuration
SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-for-jwt")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Models
class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    
class SecurityEvent(Base):
    __tablename__ = "security_events"
    
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    event_type = Column(String, index=True)
    source_ip = Column(String)
    destination_ip = Column(String)
    severity = Column(String)
    description = Column(String)
# Pydantic models
class UserBase(BaseModel):
    username: str
    
class UserCreate(UserBase):
    password: str
    
class UserInDB(UserBase):
    id: int
    hashed_password: str
    
    class Config:
        orm_mode = True
        
class User(UserBase):
    id: int
    
    class Config:
        orm_mode = True
        
class Token(BaseModel):
    access_token: str
    token_type: str
    
class TokenData(BaseModel):
    username: Optional[str] = None
    
class SecurityEventBase(BaseModel):
    event_type: str
    source_ip: str
    destination_ip: str
    severity: str
    description: str
    
class SecurityEventCreate(SecurityEventBase):
    pass
    
class SecurityEvent(SecurityEventBase):
    id: int
    timestamp: datetime
    
    class Config:
        orm_mode = True

# Database Dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Security functions
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def get_user(db: Session, username: str):
    return db.query(User).filter(User.username == username).first()

def authenticate_user(db: Session, username: str, password: str):
    user = get_user(db, username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except jwt.PyJWTError:
        raise credentials_exception
    user = get_user(db, username=token_data.username)
    if user is None:
        raise credentials_exception
    return user

# FastAPI App
app = FastAPI(title="SIEM Dashboard API")

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # For development only, restrict in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize database
@app.on_event("startup")
async def startup():
    Base.metadata.create_all(bind=engine)
    
    # Add a default user if none exists
    db = SessionLocal()
    if db.query(User).count() == 0:
        default_user = User(username="admin", hashed_password=get_password_hash("password"))
        db.add(default_user)
        db.commit()
    
    # Add some mock security events if none exist
    if db.query(SecurityEvent).count() == 0:
        mock_events = [
            SecurityEvent(
                event_type="Brute Force Attack",
                source_ip="192.168.1.100",
                destination_ip="10.0.0.5",
                severity="High",
                description="Multiple failed login attempts detected",
                timestamp=datetime.utcnow() - timedelta(hours=2)
            ),
            SecurityEvent(
                event_type="SQL Injection Attempt",
                source_ip="192.168.1.101",
                destination_ip="10.0.0.6",
                severity="Critical",
                description="SQL injection pattern detected in web request",
                timestamp=datetime.utcnow() - timedelta(hours=1)
            ),
            SecurityEvent(
                event_type="Malware Detection",
                source_ip="192.168.1.103",
                destination_ip="10.0.0.7",
                severity="Medium",
                description="Potential malware signature detected in network traffic",
                timestamp=datetime.utcnow() - timedelta(minutes=30)
            ),
            SecurityEvent(
                event_type="Suspicious File Access",
                source_ip="192.168.1.104",
                destination_ip="10.0.0.8",
                severity="Low",
                description="Unusual file access pattern detected",
                timestamp=datetime.utcnow() - timedelta(minutes=15)
            ),
            SecurityEvent(
                event_type="Unauthorized Access",
                source_ip="192.168.1.105",
                destination_ip="10.0.0.9",
                severity="High",
                description="Unauthorized access to restricted system resource",
                timestamp=datetime.utcnow() - timedelta(minutes=5)
            ),
        ]
        db.add_all(mock_events)
        db.commit()
    db.close()
# Authentication
@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/users/me", response_model=User)
async def read_users_me(current_user: User = Depends(get_current_user)):
    return current_user

# Security Events API
@app.get("/security-events", response_model=List[SecurityEvent])
async def get_security_events(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    skip: int = 0,
    limit: int = 100
):
    events = db.query(SecurityEvent).order_by(SecurityEvent.timestamp.desc()).offset(skip).limit(limit).all()
    return events

# Health check endpoint
@app.get("/health")
async def health_check():
    return {"status": "ok"}
