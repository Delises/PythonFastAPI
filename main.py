from fastapi import FastAPI
from api import get_cve

app = FastAPI()
app.include_router(get_cve.router)
