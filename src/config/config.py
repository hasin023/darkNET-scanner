import os
from dotenv import load_dotenv

load_dotenv()

# Application Config
APP_NAME = "DarkNET_Scanner"
VERSION = "v1.0.0"

# Database Config
DB_USERNAME = os.getenv("DB_USERNAME", "postgres")
DB_PASSWORD = os.getenv("DB_PASSWORD", "pgadmin")
DB_PORT = int(os.getenv("DB_PORT", "5432"))
DB_HOST = os.getenv("DB_HOST", "localhost")
DB_NAME = os.getenv("DB_NAME", "darknet-scanner")
DB_URI = f'postgresql://{DB_USERNAME}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}'

# JWT Config
SECRET_KEY = os.getenv("SECRET_KEY", "55VoicesInMyHeadAndTheyAllWantMeToListenToThem")
ALGORITHM = os.getenv("ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN expire minutes", 30))