import json
import xmltojson
import subprocess
from fastapi import HTTPException
from sqlalchemy.orm import Session
from src.models.scan import ScanModel
from .schema import ScanCreate, ScanUpdate, ScanResponse
from datetime import datetime, timezone
from src.core import web_scanner

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
        Run a port scan using Nmap and update the scan results.
        """
        try:
            command = ["nmap", "-p1-1024", "-oX", "-", scan.target_ip]
            output = subprocess.check_output(command, universal_newlines=True)
            outputJson = xmltojson.parse(output)
            nmap_data = json.loads(outputJson)
            
            scanner = nmap_data["nmaprun"]["@scanner"]
            args = nmap_data["nmaprun"]["@args"]
            start_time = nmap_data["nmaprun"]["@startstr"]
            num_services = nmap_data["nmaprun"]["scaninfo"]["@numservices"]
            num_hosts_up = nmap_data["nmaprun"]["runstats"]["hosts"]["@up"]
            num_hosts_down = nmap_data["nmaprun"]["runstats"]["hosts"]["@down"]
            num_hosts_total = nmap_data["nmaprun"]["runstats"]["hosts"]["@total"]
            scan_duration = nmap_data["nmaprun"]["runstats"]["finished"]["@elapsed"]
            scan_status = nmap_data["nmaprun"]["runstats"]["finished"]["@exit"]
                        
            port_results = {
                "scanner": scanner,
                "args": args,
                "start_time": start_time,
                "num_services": num_services,
                "num_hosts_up": num_hosts_up,
                "num_hosts_down": num_hosts_down,
                "num_hosts_total": num_hosts_total,
                "scan_duration": scan_duration,
                "scan_status": scan_status,
            }

            scan.results = json.dumps(port_results)
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
            scanner = web_scanner.VulnerabilityScanner()
            scanner.scan(scan.target_ip)
            
            scan.results = scanner.report_vulnerabilities()
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
