"""Pytest configuration and fixtures."""


def pytest_configure(config):
    """Register custom markers."""
    config.addinivalue_line(
        'markers',
        'integration: hits the live OTX API (requires OTX_API_KEY)',
    )
