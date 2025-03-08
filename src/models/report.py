from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, JSON
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from datetime import datetime
import uuid

Base = declarative_base()

class ReportModel(Base):
    __tablename__ = "reports"
    
    report_id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer)
    user_id = Column(Integer)
    generated_at = Column(DateTime, default=datetime.utcnow)
    report_title = Column(String)
    report_summary = Column(String)
    severity_level = Column(String)
    recommendations = Column(JSON)
    details = Column(JSON)