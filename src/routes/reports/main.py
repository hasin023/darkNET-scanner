from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from src import get_db
from .schema import ScanCreate, ScanResponse
from .controller import ScanController
from src.routes.users.controller import UserController

router = APIRouter(
    prefix="/api/reports",
    tags=["Reports"],
    responses={404: {"description": "Not found"}},
)

@router.get("/", response_model=ScanResponse, dependencies=[Depends(UserController.get_auth_user)])
async def create_scan_route(scan_data: ScanCreate, db: Session = Depends(get_db)):
    return await ScanController.create_scan(scan_data, db)

@router.get("/{scan_id}", response_model=ScanResponse, dependencies=[Depends(UserController.get_auth_user)])
async def get_scan_route(scan_id: int, db: Session = Depends(get_db)):
    return await ScanController.get_scan(scan_id, db)