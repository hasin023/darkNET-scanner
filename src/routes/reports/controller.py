import asyncio
import json
import secrets
import requests
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
    async def  create_scan(scan_data: ScanCreate, db: Session):
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
        Tests password strength, session security, and brute force protection.
        """
        try:
            target_url = scan.target_ip.rstrip('/')  # Remove trailing slash if present
            results = {
                "target_url": target_url,
                "issues": [],
                "details": {
                    "password_policy": {},
                    "session_security": {},
                    "brute_force": {}
                }
            }

            # 1. Test Password Policy
            test_passwords = [
                {"password": "short", "expected_issues": ["length"]},
                {"password": "password123", "expected_issues": ["common", "uppercase"]},
                {"password": "abcdefgh", "expected_issues": ["number", "uppercase"]},
                {"password": "12345678", "expected_issues": ["letter", "uppercase"]}
            ]
            
            password_requirements = {
                "min_length": False,
                "uppercase": False,
                "numbers": False,
                "special_chars": False,
                "prevents_common": False
            }

            try:
                for test in test_passwords:
                    register_response = requests.post(
                        f"{target_url}/register",
                        json={
                            "username": f"test_user_{secrets.token_hex(4)}",
                            "email": f"test_{secrets.token_hex(4)}@example.com",
                            "password": test["password"]
                        },
                        timeout=10,
                        verify=False  # Allow self-signed certificates
                    )
                    
                    error_msg = register_response.text.lower()
                    
                    # Enhanced pattern matching
                    if any(phrase in error_msg for phrase in ["length", "too short", "minimum"]):
                        password_requirements["min_length"] = True
                    if any(phrase in error_msg for phrase in ["uppercase", "capital"]):
                        password_requirements["uppercase"] = True
                    if any(phrase in error_msg for phrase in ["number", "digit"]):
                        password_requirements["numbers"] = True
                    if any(phrase in error_msg for phrase in ["special", "symbol"]):
                        password_requirements["special_chars"] = True
                    if any(phrase in error_msg for phrase in ["common", "weak", "dictionary"]):
                        password_requirements["prevents_common"] = True

                results["details"]["password_policy"] = {
                    "requirements": password_requirements,
                    "missing_requirements": [k for k, v in password_requirements.items() if not v]
                }
                
                if results["details"]["password_policy"]["missing_requirements"]:
                    results["issues"].append("Weak password policy detected")
                    
            except requests.RequestException as e:
                results["issues"].append(f"Password policy test failed: {str(e)}")

            # 2. Test Session Security
            try:
                login_response = requests.post(
                    f"{target_url}/login",
                    json={
                        "username": "test_user",
                        "password": "Test123!@#"
                    },
                    timeout=10,
                    verify=False,
                    allow_redirects=True
                )
                
                session_security = {
                    "secure_flag": False,
                    "httponly_flag": False,
                    "samesite": False,
                    "session_timeout": False
                }

                if login_response.cookies:
                    for cookie in login_response.cookies:
                        if cookie.name.lower() in ['session', 'sessionid', 'token', 'auth']:
                            session_security["secure_flag"] = cookie.secure
                            session_security["httponly_flag"] = cookie.has_nonstandard_attr('HttpOnly')
                            session_security["samesite"] = any(
                                attr.lower() == 'samesite' 
                                for attr in cookie._rest.keys()
                            )

                    results["details"]["session_security"] = session_security
                    
                    # Check for missing security flags
                    missing_flags = [k for k, v in session_security.items() if not v]
                    if missing_flags:
                        results["issues"].append(
                            f"Session cookie missing security flags: {', '.join(missing_flags)}"
                        )

                # Check for JWT in Authorization header
                auth_header = login_response.headers.get('Authorization')
                if auth_header and auth_header.startswith('Bearer '):
                    results["details"]["session_security"]["jwt_used"] = True
                    
            except requests.RequestException as e:
                results["issues"].append(f"Session security test failed: {str(e)}")

            # 3. Test Brute Force Protection
            try:
                attempt_count = 0
                max_attempts = 7  # Increased attempts to better detect rate limiting
                
                for i in range(max_attempts):
                    response = requests.post(
                        f"{target_url}/login",
                        json={
                            "username": "test_user",
                            "password": f"wrong_password_{i}"
                        },
                        timeout=5,
                        verify=False
                    )
                    attempt_count += 1

                    # Check for rate limiting or account lockout
                    if response.status_code in [429, 423]:  # Too Many Requests or Locked
                        results["details"]["brute_force"] = {
                            "protection": "Implemented",
                            "threshold": attempt_count,
                            "type": "Rate limiting" if response.status_code == 429 else "Account lockout"
                        }
                        break
                    
                    # Add small delay between attempts
                    await asyncio.sleep(0.5)
                
                if attempt_count == max_attempts:
                    results["issues"].append("No brute force protection detected")
                    results["details"]["brute_force"] = {
                        "protection": "Not implemented",
                        "attempts_allowed": f"More than {max_attempts}"
                    }
                    
            except requests.RequestException as e:
                results["issues"].append(f"Brute force protection test failed: {str(e)}")

            # Update scan with final results
            scan.results = json.dumps(results)
            scan.status = "completed"
            scan.end_time = datetime.now(timezone.utc)
            db.commit()
        except Exception as e:
            scan.status = "failed"
            scan.end_time = datetime.now(timezone.utc)
            db.commit()
            raise HTTPException(
                status_code=400, 
                detail=f"Authentication test failed: {str(e)}"
            )