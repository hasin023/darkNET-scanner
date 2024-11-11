from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from src import get_db
from .controller import UserController
from .schema import UserCreate, User

router = APIRouter(
    prefix="/api/users",
    tags=["users"]
)

@router.get("/", response_model=list[User])
async def get_users(db: Session = Depends(get_db)):
    return await UserController.get_users(db)

@router.post("/", response_model=User)
async def create_user(user: UserCreate, db: Session = Depends(get_db)):
    return await UserController.create_user(user, db)

@router.get("/{user_id}", response_model=User)
async def get_user(user_id: int, db: Session = Depends(get_db)):
    return await UserController.get_user(user_id, db)