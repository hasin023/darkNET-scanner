from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session
from fastapi.security import OAuth2PasswordRequestForm

from src import get_db
from .controller import UserController
from .schema import UserCreate, User

router = APIRouter(
    prefix="/api/users",
    tags=["users"]
)

@router.post("/register", response_model=User)
async def register(user: UserCreate, db: Session = Depends(get_db)):
    return await UserController.create_user(user, db)

@router.post("/login")
async def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    return await UserController.login_for_access_token(form_data, db)

@router.post("/profile", response_model=User)
async def profile(request: Request, db: Session = Depends(get_db)):
    body = await request.json()
    token = body.get("access_token")
    
    if not token:
        raise HTTPException(status_code=400, detail="Access token is required")
    
    return await UserController.get_user_profile(token, db)

@router.get("/", response_model=list[User])
async def get_users(db: Session = Depends(get_db)):
    return await UserController.get_users(db)

@router.get("/{user_id}", response_model=User)
async def get_user(user_id: int, db: Session = Depends(get_db)):
    return await UserController.get_user(user_id, db)
