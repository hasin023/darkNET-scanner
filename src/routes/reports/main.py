from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from src import get_db
from .controller import ReportController
from .schema import ReportResponse
from src.routes.users.controller import UserController

router = APIRouter(
    prefix="/api/reports",
    tags=["Reports"],
    responses={404: {"description": "Not found"}},
)

@router.get("/{scan_id}", response_model=ReportResponse, dependencies=[Depends(UserController.get_auth_user)])
async def get_report_route(scan_id: int, db: Session = Depends(get_db)):
    return await ReportController.get_scan(scan_id, db)