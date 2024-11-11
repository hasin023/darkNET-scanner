from pydantic import BaseModel, EmailStr

class UserBase(BaseModel):
    username: str
    email: EmailStr
    role: str = "tester"

class UserCreate(UserBase):
    password: str
    
class UserLoginRequest(BaseModel):
    username: str
    password: str

class User(UserBase):
    user_id: int
    verified: bool = False

    class Config:
        from_attributes = True