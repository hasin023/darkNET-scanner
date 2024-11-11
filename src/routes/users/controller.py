from fastapi import Depends, HTTPException, Request
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from jose import jwt, JWTError
from sqlalchemy.orm import Session
from datetime import datetime, timedelta, timezone

from .schema import UserCreate
from src import get_db
from src.models.user import UserModel
from src import SECRET_KEY, ALGORITHM, ACCESS_TOKEN_EXPIRE_MINUTES

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

class UserController:
    
    @staticmethod
    async def authenticate_user(username: str, password: str, db: Session) -> bool:
        user = db.query(UserModel).filter(UserModel.username == username).first()
        if not user or user.password != password:
            return False
        return user

    @staticmethod
    async def create_access_token(data: dict, expires_delta: timedelta | None = None) -> str:
        to_encode = data.copy()
        expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=15))
        to_encode.update({"exp": expire})
        encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
        return encoded_jwt

    @staticmethod
    async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
        user = await UserController.authenticate_user(form_data.username, form_data.password, db)
        if not user:
            raise HTTPException(
                status_code=400,
                detail="Incorrect username or password",
                headers={"WWW-Authenticate": "Bearer"}
            )
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = await UserController.create_access_token(
            data={"sub": user.username},
            expires_delta=access_token_expires
        )
        return {"access_token": access_token, "token_type": "bearer"}

    @staticmethod
    async def verify_token(token: str = Depends(oauth2_scheme)) -> str:
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            username: str = payload.get("sub")
            if username is None:
                raise HTTPException(status_code=400, detail="Invalid token")
        except JWTError:
            raise HTTPException(status_code=400, detail="Invalid token")
        return username
    
    @staticmethod
    async def get_user_profile(token: str, db: Session):
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            username = payload.get("sub")
            if username is None:
                raise HTTPException(status_code=401, detail="Invalid token")
        except jwt.JWTError:
            raise HTTPException(status_code=401, detail="Invalid token")
        
        user = db.query(UserModel).filter(UserModel.username == username).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        return user

    @staticmethod
    async def create_user(user: UserCreate, db: Session = Depends(get_db)):
        # Check if username exists
        if db.query(UserModel).filter(UserModel.username == user.username).first():
            raise HTTPException(status_code=400, detail="Username already registered")
        
        # Check if email exists
        if db.query(UserModel).filter(UserModel.email == user.email).first():
            raise HTTPException(status_code=400, detail="Email already registered")
        
        # Create new user
        db_user = UserModel(
            username=user.username,
            email=user.email,
            password=user.password,
            role=user.role,
            verified=False
        )
        
        try:
            db.add(db_user)
            db.commit()
            db.refresh(db_user)
            return db_user
        except Exception as e:
            db.rollback()
            raise HTTPException(status_code=500, detail=str(e))
        
        
    @staticmethod
    async def get_users(db: Session = Depends(get_db)):
        users = db.query(UserModel).all()
        return users

    @staticmethod
    async def get_user(user_id: int, db: Session = Depends(get_db)):
        user = db.query(UserModel).filter(UserModel.user_id == user_id).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        return user