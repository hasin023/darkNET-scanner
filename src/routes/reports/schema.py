from pydantic import BaseModel
from datetime import datetime
from typing import Optional, List, Dict

class ScanBase(BaseModel):
    user_id: int
    target_ip: str
    scan_type: str

class ScanCreate(ScanBase):
    pass

class ScanUpdate(BaseModel):
    status: Optional[str]
    results: Optional[Dict]
    end_time: Optional[datetime]

class ScanResponse(ScanBase):
    scan_id: int
    status: str
    start_time: datetime
    end_time: Optional[datetime]
    results: Optional[Dict]

    class Config:
        from_attributes = True