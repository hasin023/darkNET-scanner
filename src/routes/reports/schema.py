from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional
from datetime import datetime

class ReportBase(BaseModel):
    report_id: Optional[int] = None
    scan_id: int
    user_id: int
    generated_at: datetime = Field(default_factory=datetime.now)
    report_title: str
    report_summary: str
    severity_level: str
    recommendations: List[str]

class AuthTestReportDetails(BaseModel):
    failed_tests: List[str]
    password_policy_details: Dict[str, Any] = {}
    session_security_details: Dict[str, Any] = {}
    brute_force_details: Dict[str, Any] = {}

class WebScanReportDetails(BaseModel):
    vulnerabilities: List[str]
    risk_level: str
    impact_assessment: str
    vulnerability_details: Dict[str, Any] = {}

class PortScanReportDetails(BaseModel):
    scan_status: str
    hosts_scanned: int
    hosts_up: int
    hosts_down: int
    scan_duration: float
    open_ports: List[int] = []
    services_detected: Dict[str, Any] = {}

class ReportDetails(BaseModel):
    auth_test: Optional[AuthTestReportDetails] = None
    web_scan: Optional[WebScanReportDetails] = None
    port_scan: Optional[PortScanReportDetails] = None

class ReportCreate(ReportBase):
    details: ReportDetails

class Report(ReportBase):
    details: ReportDetails
    
    class Config:
        orm_mode = True

class ReportResponse(BaseModel):
    success: bool
    message: str
    report: Optional[Report] = None
