from fastapi import APIRouter
from .controller import UserController
from .schemas import UserCreate

router = APIRouter(
    prefix="/api/users",
    tags=["users"]
)

@router.get("/")
async def get_users():
    return await UserController.get_users()

@router.post("/")
async def create_user(user: UserCreate):
    return await UserController.create_user(user)

@router.get("/{user_id}")
async def get_user(user_id: int):
    return await UserController.get_user(user_id)