-- Create the database
DROP DATABASE IF EXISTS "darknet-scanner";

CREATE DATABASE "darknet-scanner";

-- Create users table
CREATE TABLE USERS (
    USER_ID SERIAL PRIMARY KEY,
    USERNAME VARCHAR(50) UNIQUE NOT NULL,
    EMAIL VARCHAR(100) UNIQUE NOT NULL,
    PASSWORD VARCHAR(255) NOT NULL,
    ROLE VARCHAR(20) NOT NULL DEFAULT 'user',
    VERIFIED BOOLEAN NOT NULL DEFAULT FALSE
);

-- Create index for faster lookups
CREATE INDEX IDX_USERNAME ON USERS(USERNAME);

CREATE INDEX IDX_EMAIL ON USERS(EMAIL);

-- Insert into users
INSERT INTO USERS (
    USERNAME,
    EMAIL,
    PASSWORD,
    ROLE,
    VERIFIED
) VALUES (
    'hasin023',
    'hasin@yahoo.com',
    '$2b$12$1Zw3MWV5YKyZWxH1ZKqHB.2PQTlGOHW1lBxICaNvxgBAE7NEYsH1G',
    'tester',
    TRUE
),
(
    'mahin009',
    'mahin@yahoo.com',
    '$2b$12$1Zw3MWV5YKyZWxH1ZKqHB.2PQTlGOHW1lBxICaNvxgBAE7NEYsH1G',
    'tester',
    FALSE
),
(
    'nahiyan',
    'nahiyan@yahoo.com',
    '$2b$12$1Zw3MWV5YKyZWxH1ZKqHB.2PQTlGOHW1lBxICaNvxgBAE7NEYsH1G',
    'hacker',
    FALSE
);

CREATE TABLE SCANS (
    SCAN_ID SERIAL PRIMARY KEY,
    USER_ID INTEGER,
    TARGET_IP VARCHAR(255),
    SCAN_TYPE VARCHAR(255),
    STATUS VARCHAR(255),
    START_TIME TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    END_TIME TIMESTAMP WITH TIME ZONE,
    RESULTS JSON
);

CREATE TABLE reports (
    report_id SERIAL PRIMARY KEY,
    scan_id INTEGER REFERENCES scans(scan_id),
    user_id INTEGER,
    generated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    report_title TEXT,
    report_summary TEXT,
    severity_level TEXT,
    recommendations JSONB,
    details JSONB
);

CREATE INDEX idx_reports_report_id ON reports(report_id);
