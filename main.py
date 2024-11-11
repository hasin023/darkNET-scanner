from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from starlette.responses import RedirectResponse

from src import APP_NAME, VERSION
from src.routes import users_router
from src import models
from src import engine

app = FastAPI(
    title=APP_NAME,
    version=VERSION
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
    allow_credentials=True
)

# Include all routers
app.include_router(users_router)

# Create tables
models.user.Base.metadata.create_all(bind=engine)

# Redirect / -> Swagger-UI documentation
@app.get("/")
def main_function():
    """
    Redirect to documentation (`/docs/`).
    """
    return RedirectResponse(url="/docs/")