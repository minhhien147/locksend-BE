"""routers — FastAPI router package."""
from routers.auth_router import router as auth_router
from routers.download_router import router as download_router
from routers.files_router import router as files_router
from routers.integrations_router import router as integrations_router
from routers.keys_router import router as keys_router
from routers.token_security_router import router as token_security_router
from routers.upload_router import router as upload_router
from routers.vault_router import router as vault_router

__all__ = [
    "auth_router",
    "download_router",
    "files_router",
    "integrations_router",
    "keys_router",
    "token_security_router",
    "upload_router",
    "vault_router",
]
