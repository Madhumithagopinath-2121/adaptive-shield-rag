"""Application configuration management using Pydantic Settings."""

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Configuration settings for AdaptiveShield RAG backend."""

    app_name: str = "AdaptiveShield RAG"
    app_env: str = "development"
    app_host: str = "0.0.0.0"
    app_port: int = 8000
    debug: bool = True
    log_level: str = "INFO"
    sqlite_db_path: str = "data/adaptiveshield.db"
    risk_threshold_quarantine: float = 0.40
    risk_threshold_block: float = 0.70

    # Threat State and Attack Velocity parameters
    attack_velocity_window_seconds: int = 300
    threat_threshold_elevated_velocity: float = 0.10
    threat_threshold_elevated_block_rate: float = 0.05
    threat_threshold_high_velocity: float = 0.25
    threat_threshold_high_block_rate: float = 0.15
    threat_threshold_critical_velocity: float = 0.50
    threat_threshold_critical_block_rate: float = 0.30

    @model_validator(mode="after")
    def validate_thresholds(self) -> "Settings":
        """Validate that 0.0 <= quarantine < block <= 1.0."""
        if not (
            0.0 <= self.risk_threshold_quarantine < self.risk_threshold_block <= 1.0
        ):
            raise ValueError(
                f"Invalid risk thresholds: must satisfy 0.0 <= quarantine "
                f"({self.risk_threshold_quarantine}) < block ({self.risk_threshold_block}) <= 1.0"
            )
        return self

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )


settings = Settings()
