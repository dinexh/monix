"""
Pytest configuration and shared fixtures for Monix tests.
"""

import pytest
from unittest.mock import Mock, MagicMock
from datetime import datetime, timedelta


@pytest.fixture
def mock_log_entries():
    """Sample log entries for testing traffic analysis."""
    from core.analyzers.traffic import LogEntry
    
    base_time = datetime.utcnow()
    return [
        LogEntry(
            ip="192.168.1.100",
            timestamp=base_time,
            method="GET",
            url="/",
            status=200,
            user_agent="Mozilla/5.0",
            size=1234
        ),
        LogEntry(
            ip="192.168.1.101",
            timestamp=base_time - timedelta(minutes=1),
            method="GET",
            url="/wp-admin",
            status=404,
            user_agent="sqlmap/1.0",
            size=0
        ),
        LogEntry(
            ip="192.168.1.101",
            timestamp=base_time - timedelta(minutes=2),
            method="POST",
            url="/admin",
            status=403,
            user_agent="sqlmap/1.0",
            size=0
        ),
    ]


@pytest.fixture
def mock_system_stats():
    """Mock system statistics for testing."""
    return {
        "cpu_percent": 45.5,
        "memory_percent": 60.2,
        "disk_percent": 75.0,
        "network_sent": 1024000,
        "network_recv": 2048000,
    }


@pytest.fixture
def mock_connections():
    """Mock network connections for testing."""
    return [
        {
            "local_address": "192.168.1.10:22",
            "remote_address": "203.0.113.0:45678",
            "status": "ESTABLISHED",
            "pid": 1234,
        },
        {
            "local_address": "0.0.0.0:80",
            "remote_address": "*:*",
            "status": "LISTEN",
            "pid": 5678,
        },
    ]


@pytest.fixture
def sample_nginx_log_line():
    """Sample Nginx log line in combined format."""
    return '192.168.1.100 - - [07/Feb/2026:10:30:00 +0000] "GET /test HTTP/1.1" 200 1234 "-" "Mozilla/5.0"'


@pytest.fixture
def sample_suspicious_log_line():
    """Sample suspicious Nginx log line."""
    return '203.0.113.50 - - [07/Feb/2026:10:30:00 +0000] "GET /wp-login.php HTTP/1.1" 404 0 "-" "sqlmap/1.0"'


@pytest.fixture
def mock_flask_app():
    """Create a Flask test client."""
    from api.server import app
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client
