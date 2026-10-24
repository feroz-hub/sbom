"""Local operational harness: real native routers and DB, no fake authentication.

Started only by explicitly opted-in acceptance tests against disposable DBs.
"""

from app.routers.native_auth import router
from app.routers.platform import router as platform
from app.routers.tenants import router as tenants
from fastapi import FastAPI

app = FastAPI()
app.include_router(router)
app.include_router(tenants)
app.include_router(platform)


@app.get("/health")
def health():
    return {"ready": True}
