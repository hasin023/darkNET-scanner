import json
from fastapi import HTTPException
from sqlalchemy.orm import Session
from src.models.scan import ScanModel
from .schema import ScanCreate, ScanUpdate, ScanResponse
from datetime import datetime, timezone

class ScanController:
    
    @staticmethod
    async def create_scan(scan_data: ScanCreate, db: Session):
        """
        Create a new scan.
        """
        scan = ScanModel(
            user_id=scan_data.user_id,
            target_ip=scan_data.target_ip,
            scan_type=scan_data.scan_type,
            status="pending",
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)
        return ScanResponse.model_validate(scan)

    @staticmethod
    async def get_scan(scan_id: int, db: Session):
        """
        Retrieve a specific scan.
        """
        scan = db.query(ScanModel).filter(ScanModel.scan_id == scan_id).first()
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        # Deserialize the results to dictionary
        if scan.results:
            scan.results = json.loads(scan.results) if isinstance(scan.results, str) else scan.results
        return ScanResponse.model_validate(scan)

    @staticmethod
    async def run_scan(scan_id: int, db: Session):
        """
        Run a specific scan.
        """
        scan = db.query(ScanModel).filter(ScanModel.scan_id == scan_id).first()
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        # Run the appropriate scan based on the scan_type
        if scan.scan_type == "port_scan":
            await ScanController.run_port_scan(scan, db)
        elif scan.scan_type == "web_scan":
            await ScanController.run_web_scan(scan, db)
        elif scan.scan_type == "auth_test":
            await ScanController.run_auth_test(scan, db)
        else:
            raise HTTPException(status_code=400, detail="Invalid scan type")
        
        # Deserialize the results to dictionary
        if scan.results:
            scan.results = json.loads(scan.results) if isinstance(scan.results, str) else scan.results
        
        return ScanResponse.model_validate(scan)

    @staticmethod
    async def run_port_scan(scan: ScanModel, db: Session):
        """
        Run a port scan with elevated privileges.
        """
        try:
            # Placeholder for Port scan logic
            scan.results = json.dumps({"message": "Port scan results"})  # Save as string in DB
            scan.status = "completed"
            scan.end_time = datetime.now(timezone.utc)
            db.commit()
        except Exception as e:
            scan.status = "failed"
            scan.end_time = datetime.now(timezone.utc)
            db.commit()
            raise HTTPException(status_code=400, detail=str(e))

    @staticmethod
    async def run_web_scan(scan: ScanModel, db: Session):
        """
        Run a web scan and update the scan results.
        """
        try:
            # Placeholder for web scan logic
            scan.results = json.dumps({"message": "Web scan results"})  # Save as string in DB
            scan.status = "completed"
            scan.end_time = datetime.now(timezone.utc)
            db.commit()
        except Exception as e:
            scan.status = "failed"
            scan.end_time = datetime.now(timezone.utc)
            db.commit()
            raise HTTPException(status_code=400, detail=str(e))
        
    @staticmethod
    async def run_auth_test(scan: ScanModel, db: Session):
        """
        Run an authentication test and update the scan results.
        """
        try:
            # Placeholder for auth test logic
            scan.results = json.dumps({"message": "Authentication test results"})  # Save as string in DB
            scan.status = "completed"
            scan.end_time = datetime.now(timezone.utc)
            db.commit()
        except Exception as e:
            scan.status = "failed"
            scan.end_time = datetime.now(timezone.utc)
            db.commit()
            raise HTTPException(status_code=400, detail=str(e))
