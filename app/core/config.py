
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "CloudGuard"
    app_env: str = "development"
    database_url: str = "sqlite:///./cloudguard.db"
    azure_subscription_id: str | None = None
    api_token: str | None = None

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


settings = Settings()
