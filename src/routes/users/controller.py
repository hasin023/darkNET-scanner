from fastapi import Depends, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from jose import jwt, JWTError
from sqlalchemy.orm import Session
from typing import Union
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
            data={"user": user.username, "role": user.role},
            expires_delta=access_token_expires
        )
        return {"access_token": access_token, "token_type": "bearer"}

    @staticmethod
    async def verify_token(request: Request, db: Session = Depends(get_db)):
        try:
            token = request.headers.get("Authorization")
            if not token:
                raise HTTPException(status_code=401, detail="No token provided")
            token = token.split()[1]
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            username: str = payload.get("user")
            role: str = payload.get("role")
            if username is None or role is None:
                raise HTTPException(status_code=401, detail="Invalid token")
            user = db.query(UserModel).filter(UserModel.username == username).first()
            if not user or user.role != role:
                raise HTTPException(status_code=403, detail="Unauthorized")
            return user
        except JWTError:
            raise HTTPException(status_code=401, detail="Invalid token")
    
    @staticmethod
    async def get_user_profile(token: str, db: Session):
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            username = payload.get("user")
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
        
        if db.query(UserModel).filter(UserModel.username == user.username).first():
            raise HTTPException(status_code=400, detail="Username already registered")
        if db.query(UserModel).filter(UserModel.email == user.email).first():
            raise HTTPException(status_code=400, detail="Email already registered")
        
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
        
    # Admin login
    @staticmethod
    async def admin_login(username: str, password: str, db: Session = Depends(get_db)):
        user = db.query(UserModel).filter(UserModel.username == username).first()
        if not user or user.password != password or not user.role == "admin":
            raise HTTPException(status_code=400, detail="Incorrect username, password or user is not an admin")
        access_token = await UserController.create_access_token(data={"user": user.username})
        response = JSONResponse(content={"message": "Logged in successfully", "access_token": access_token})
        response.set_cookie(key="session-token", value=access_token, httponly=True)
        return response
    
    @staticmethod
    async def get_admin_profile(request: Request, db: Session = Depends(get_db)):
        user = await UserController.get_auth_user(request, db)
        return user
    
    @staticmethod
    async def admin_logout(response: Response):
        response.delete_cookie("session-token")
        return {"message": "Admin logged out successfully"}

    @staticmethod
    async def create_access_token(data: dict, expires_delta: Union[timedelta, None] = None):
        to_encode = data.copy()
        if expires_delta:
            expire = datetime.now(timezone.utc) + expires_delta
        else:
            expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        to_encode.update({"exp": expire})
        encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
        return encoded_jwt

    @staticmethod
    async def get_auth_user(request: Request, db: Session = Depends(get_db)):
        try:
            token = request.cookies.get("session-token")
            if not token:
                raise HTTPException(status_code=401, detail="User not Authenticated")
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            username: str = payload.get("user")
            if username is None:
                raise HTTPException(status_code=401, detail="Invalid token")
            user = db.query(UserModel).filter(UserModel.username == username).first()
            if not user or not user.role == "admin":
                raise HTTPException(status_code=403, detail="Unauthorized")
            return user
        except JWTError:
            raise HTTPException(status_code=401, detail="Invalid token")
        
        
    @staticmethod
    async def get_users(request: Request, db: Session = Depends(get_db)):
        user = await UserController.get_auth_user(request, db)
        if not user or user.role != "admin":
            raise HTTPException(status_code=403, detail="Unauthorized")
        users = db.query(UserModel).all()
        return users

    @staticmethod
    async def get_user(request: Request, username: str, db: Session = Depends(get_db)):
        user = await UserController.get_auth_user(request, db)
        if not user or user.role != "admin":
            raise HTTPException(status_code=403, detail="Unauthorized")
        user_obj = db.query(UserModel).filter(UserModel.username == username).first()
        if not user_obj:
            raise HTTPException(status_code=404, detail="User not found")
        return user_obj