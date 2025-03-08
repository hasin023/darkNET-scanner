from fastapi import HTTPException
from sqlalchemy.orm import Session
from typing import Dict, Any
import json
from .schema import Report, ReportDetails, AuthTestReportDetails, WebScanReportDetails, PortScanReportDetails, ReportResponse
from src.models.scan import ScanModel
from src.models.report import ReportModel

class ReportController:
    @staticmethod
    async def get_scan(scan_id: int, db: Session):
        try:
            scan = db.query(ScanModel).filter(ScanModel.scan_id == scan_id).first()
            
            if not scan:
                raise HTTPException(status_code=404, detail=f"Scan with ID {scan_id} not found")
            
            if scan.status != "completed":
                return ReportResponse(
                    success=False,
                    message=f"Scan is in {scan.status} state. Reports can only be generated for completed scans.",
                    report=None
                )
            
            scan_results = json.loads(scan.results) if isinstance(scan.results, str) else scan.results
            
            existing_report = db.query(ReportModel).filter(ReportModel.scan_id == scan_id).first()
            if existing_report:
                if isinstance(existing_report.details, str):
                    existing_report.details = json.loads(existing_report.details)
                
                report = Report(
                    report_id=existing_report.report_id,
                    scan_id=existing_report.scan_id,
                    user_id=existing_report.user_id,
                    generated_at=existing_report.generated_at,
                    report_title=existing_report.report_title,
                    report_summary=existing_report.report_summary,
                    severity_level=existing_report.severity_level,
                    recommendations=existing_report.recommendations,
                    details=ReportDetails.parse_obj(existing_report.details)
                )
                
                return ReportResponse(
                    success=True,
                    message="Report retrieved successfully",
                    report=report
                )
            
            scan_data = {
                "scan_id": scan.scan_id,
                "user_id": scan.user_id,
                "target_ip": scan.target_ip,
                "scan_type": scan.scan_type,
                "status": scan.status,
                "start_time": scan.start_time,
                "end_time": scan.end_time,
                "results": scan_results
            }
            
            report = ReportController._generate_report_from_scan(scan_data)
            
            db_report = ReportModel(
                scan_id=report.scan_id,
                user_id=report.user_id,
                generated_at=report.generated_at,
                report_title=report.report_title,
                report_summary=report.report_summary,
                severity_level=report.severity_level,
                recommendations=report.recommendations,
                details=json.dumps(report.details.dict())
            )
            
            db.add(db_report)
            db.commit()
            db.refresh(db_report)  # Ensure report_id is set after insert
            
            report.report_id = db_report.report_id  # Assign the generated report_id
            
            return ReportResponse(
                success=True,
                message="Report generated successfully",
                report=report
            )
            
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Error generating report: {str(e)}")
    
    @staticmethod
    def _generate_report_from_scan(scan_data: Dict[str, Any]) -> Report:
        scan_type = scan_data.get("scan_type")
        scan_id = scan_data.get("scan_id")
        user_id = scan_data.get("user_id")
        target = scan_data.get("target_ip")
        results = scan_data.get("results", {})
        
        report_base = {
            "scan_id": scan_id,
            "user_id": user_id,
            "report_title": f"{scan_type.upper()} Report for {target}",
            "recommendations": []
        }
        
        details = ReportDetails()
        
        if scan_type == "auth_test":
            issues = results.get("issues", [])
            report_base["report_summary"] = f"Authentication testing revealed {len(issues)} issues."
            
            if issues:
                report_base["severity_level"] = "High"
                report_base["recommendations"] = [
                    "Implement proper URL formatting for authentication endpoints",
                    "Ensure password policy follows NIST guidelines",
                    "Implement proper session security measures",
                    "Add brute force protection mechanisms"
                ]
            else:
                report_base["severity_level"] = "Low"
                report_base["recommendations"] = ["Continue monitoring authentication systems"]
            
            details.auth_test = AuthTestReportDetails(
                failed_tests=issues,
                password_policy_details=results.get("details", {}).get("password_policy", {}),
                session_security_details=results.get("details", {}).get("session_security", {}),
                brute_force_details=results.get("details", {}).get("brute_force", {})
            )
            
        elif scan_type == "web_scan":
            vulnerabilities = results.get("vulnerabilities", [])
            report_base["report_summary"] = f"Web security scan identified {len(vulnerabilities)} vulnerabilities."
            
            has_sql_injection = any("SQL injection" in vuln for vuln in vulnerabilities)
            
            if has_sql_injection:
                report_base["severity_level"] = "Critical"
                report_base["recommendations"] = [
                    "Implement prepared statements for all database queries",
                    "Use input validation and sanitization",
                    "Apply web application firewall rules",
                    "Perform regular security audits"
                ]
            elif vulnerabilities:
                report_base["severity_level"] = "Medium"
                report_base["recommendations"] = [
                    "Review and patch identified vulnerabilities",
                    "Implement security headers",
                    "Perform regular security testing"
                ]
            else:
                report_base["severity_level"] = "Low"
                report_base["recommendations"] = ["Continue monitoring web application security"]
            
            impact = "SQL injection vulnerabilities can lead to unauthorized data access, data theft, and potentially complete system compromise." if has_sql_injection else "The identified vulnerabilities may impact application integrity and security."
            
            details.web_scan = WebScanReportDetails(
                vulnerabilities=vulnerabilities,
                risk_level=report_base["severity_level"],
                impact_assessment=impact,
                vulnerability_details={}
            )
            
        elif scan_type == "port_scan":
            scan_status = results.get("scan_status")
            hosts_total = int(results.get("num_hosts_total", 0))
            hosts_up = int(results.get("num_hosts_up", 0))
            hosts_down = int(results.get("num_hosts_down", 0))
            scan_duration = float(results.get("scan_duration", 0))
            
            report_base["report_summary"] = f"Port scan completed with status: {scan_status}. Scanned {hosts_total} hosts."
            
            if hosts_up > 0:
                report_base["severity_level"] = "Medium"
                report_base["recommendations"] = [
                    "Review open ports and services",
                    "Disable unnecessary services",
                    "Implement firewall rules"
                ]
            else:
                report_base["severity_level"] = "Low"
                report_base["recommendations"] = ["Continue monitoring network security"]
            
            details.port_scan = PortScanReportDetails(
                scan_status=scan_status,
                hosts_scanned=hosts_total,
                hosts_up=hosts_up,
                hosts_down=hosts_down,
                scan_duration=scan_duration,
                services_detected={}
            )
        
        return Report(
            **report_base,
            details=details
        )
