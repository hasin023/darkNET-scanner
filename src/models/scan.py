from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, JSON
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from datetime import datetime

Base = declarative_base()

class ScanModel(Base):
    __tablename__ = "scans"
    
    scan_id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer)
    target_ip = Column(String)
    scan_type = Column(String)
    status = Column(String)
    start_time = Column(DateTime, default=datetime.utcnow)
    end_time = Column(DateTime, nullable=True)
    results = Column(JSON)