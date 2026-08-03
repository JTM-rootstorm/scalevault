from kivra_memory.config import Settings


def test_settings_use_loopback_defaults() -> None:
    settings = Settings()

    assert settings.host == "127.0.0.1"
    assert settings.port == 8080
    assert settings.database_url is None
