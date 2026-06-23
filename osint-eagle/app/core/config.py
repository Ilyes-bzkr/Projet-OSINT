"""
Configuration globale via pydantic-settings.
Lit les variables depuis .env automatiquement.
"""

from pydantic_settings import BaseSettings
from pydantic import Field
from functools import lru_cache


class Settings(BaseSettings):
    # API Keys
    anthropic_api_key: str = Field(default="", env="ANTHROPIC_API_KEY")
    hibp_api_key: str = Field(default="", env="HIBP_API_KEY")
    github_token: str = Field(default="", env="GITHUB_TOKEN")
    rapidapi_key: str = Field(default="", env="RAPIDAPI_KEY")

    # App
    app_host: str = Field(default="127.0.0.1", env="APP_HOST")
    app_port: int = Field(default=8000, env="APP_PORT")
    debug: bool = Field(default=False, env="DEBUG")

    # Search
    max_concurrent_searches: int = Field(default=10, env="MAX_CONCURRENT_SEARCHES")
    search_timeout_seconds: int = Field(default=30, env="SEARCH_TIMEOUT_SECONDS")
    rate_limit_delay: float = Field(default=0.5, env="RATE_LIMIT_DELAY")

    # Features
    enable_dark_web: bool = Field(default=False, env="ENABLE_DARK_WEB")
    enable_data_brokers: bool = Field(default=True, env="ENABLE_DATA_BROKERS")
    enable_ai_analysis: bool = Field(default=True, env="ENABLE_AI_ANALYSIS")

    # Database
    database_url: str = Field(
        default="sqlite+aiosqlite:///./data/osint_eagle.db",
        env="DATABASE_URL"
    )

    # Logging
    log_level: str = Field(default="INFO", env="LOG_LEVEL")
    log_file: str = Field(default="data/osint_eagle.log", env="LOG_FILE")

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False


@lru_cache()
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
