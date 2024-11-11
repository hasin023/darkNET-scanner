from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, JSON
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from datetime import datetime

Base = declarative_base()

class Scan(Base):
    __tablename__ = "scans"

    scan_id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey('users.user_id'))
    target_ip = Column(String)
    scan_type = Column(String)  # port_scan, web_scan, auth_test
    status = Column(String)  # pending, running, completed, failed
    start_time = Column(DateTime, default=datetime.utcnow)
    end_time = Column(DateTime, nullable=True)
    results = Column(JSON)
    
    # Relationships
    user = relationship("UserModel", back_populates="scans")
    vulnerabilities = relationship("Vulnerability", back_populates="scan")