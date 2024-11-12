from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from src import get_db
from .schema import ScanCreate, ScanResponse
from .controller import ScanController

router = APIRouter(
    prefix="/api/scans",
    tags=["Scans"],
    responses={404: {"description": "Not found"}},
)


@router.post("/", response_model=ScanResponse)
async def create_scan_route(scan_data: ScanCreate, db: Session = Depends(get_db)):
    return await ScanController.create_scan(scan_data, db)

@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan_route(scan_id: int, db: Session = Depends(get_db)):
    return await ScanController.get_scan(scan_id, db)

@router.post("/{scan_id}/run", response_model=ScanResponse)
async def run_scan_route(scan_id: int, db: Session = Depends(get_db)):
    return await ScanController.run_scan(scan_id, db)