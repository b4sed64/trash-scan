"""Application configuration.

All values are read from the environment (or an ``.env`` file) so that no secret
is baked into an image, per PRD section 20.
"""
from __future__ import annotations

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="TRASHSCAN_", env_file=".env", extra="ignore")

    # Database -----------------------------------------------------------------
    database_url: str = "postgresql+psycopg://trashscan:trashscan@db:5432/trashscan"

    # Sessions ---------------------------------------------------------------
    session_cookie_name: str = "trashscan_session"
    csrf_cookie_name: str = "trashscan_csrf"
    csrf_header_name: str = "X-CSRF-Token"
    # Cookies are marked Secure by default; set to false only for plain-HTTP localhost.
    session_cookie_secure: bool = True
    session_idle_minutes: int = 30
    session_absolute_hours: int = 12

    # Argon2id parameters (conservative defaults; tune per deployment) ---------
    argon2_time_cost: int = 3
    argon2_memory_cost_kib: int = 65536
    argon2_parallelism: int = 2

    # CORS: the Vite dev server origin during development.
    frontend_origin: str = "http://localhost:5173"

    # Behaviour flags --------------------------------------------------------
    # When true the app performs live DNS resolution for scope previews. Tests
    # and offline environments set this to false.
    enable_dns_resolution: bool = True

    environment: str = "development"


@lru_cache
def get_settings() -> Settings:
    return Settings()
