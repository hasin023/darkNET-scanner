# src/routes/users/controller.py
from fastapi import HTTPException, Depends
from sqlalchemy.orm import Session
from src import get_db
from src.models.user import UserModel
from .schema import User, UserCreate
from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class UserController:
    @staticmethod
    def get_password_hash(password: str) -> str:
        return pwd_context.hash(password)

    @staticmethod
    async def get_users(db: Session = Depends(get_db)):
        users = db.query(UserModel).all()
        return users

    @staticmethod
    async def create_user(user: UserCreate, db: Session = Depends(get_db)):
        # Check if username exists
        if db.query(UserModel).filter(UserModel.username == user.username).first():
            raise HTTPException(status_code=400, detail="Username already registered")
        
        # Check if email exists
        if db.query(UserModel).filter(UserModel.email == user.email).first():
            raise HTTPException(status_code=400, detail="Email already registered")
        
        # Create new user
        hashed_password = UserController.get_password_hash(user.password)
        db_user = UserModel(
            username=user.username,
            email=user.email,
            password=hashed_password,
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
    async def get_user(user_id: int, db: Session = Depends(get_db)):
        user = db.query(UserModel).filter(UserModel.user_id == user_id).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        return user