from fastapi import APIRouter, Depends, HTTPException, Request, Response
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

# Token based User login
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


# Session based Admin login and authorization
@router.post("/admin/login", status_code=200)
async def admin_login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    return await UserController.admin_login(form_data.username, form_data.password, db)

@router.get("/", response_model=list[User], dependencies=[Depends(UserController.get_auth_user)])
async def get_users(request: Request, db: Session = Depends(get_db)):
    return await UserController.get_users(request, db)

@router.get("/{username}", response_model=User, dependencies=[Depends(UserController.get_auth_user)])
async def get_user(request: Request, username: str, db: Session = Depends(get_db)):
    return await UserController.get_user(request, username, db)

@router.post("/admin/logout", status_code=200)
async def admin_logout(response: Response):
    return await UserController.admin_logout(response)