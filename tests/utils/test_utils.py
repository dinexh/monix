"""Tests for utility modules."""

import pytest
from unittest.mock import patch, Mock


class TestDisplayModule:
    """Tests for utils.display module."""

    def test_format_bytes(self):
        """Test byte formatting function."""
        from utils.display import format_bytes
        
        assert format_bytes(0) == "0.0 B"
        assert format_bytes(1024) == "1.0 KB"
        assert format_bytes(1024 * 1024) == "1.0 MB"
        assert format_bytes(1024 * 1024 * 1024) == "1.0 GB"

    def test_truncate(self):
        """Test text truncation function."""
        from utils.display import truncate
        
        assert truncate("") == ""
        assert truncate("short") == "short"
        assert truncate("this is a very long text that needs truncating", max_length=10) == "this is..."

    def test_get_threat_level(self):
        """Test threat level classification."""
        from utils.display import get_threat_level
        
        assert get_threat_level(0) == "secure"
        assert get_threat_level(1) == "warning"
        assert get_threat_level(3) == "critical"


class TestNetworkModule:
    """Tests for utils.network module."""

    def test_hex_ip_conversion(self):
        """Test hex to IP conversion."""
        from utils.network import hex_ip
        
        # Test basic hex IP conversion
        result = hex_ip("0100007F")  # 127.0.0.1 in hex
        assert isinstance(result, str)

    def test_hex_port_conversion(self):
        """Test hex to port conversion."""
        from utils.network import hex_port
        
        assert hex_port("0050") == 80  # HTTP port
        assert hex_port("01BB") == 443  # HTTPS port


class TestLoggerModule:
    """Tests for utils.logger module."""

    def test_log_functions_exist(self):
        """Test logger functions exist."""
        from utils import logger
        
        assert hasattr(logger, 'log_info')
        assert hasattr(logger, 'log_warn')
        assert hasattr(logger, 'log_error')
        assert hasattr(logger, 'log_success')

    def test_colors_defined(self):
        """Test color codes are defined."""
        from utils.logger import Colors
        
        assert hasattr(Colors, 'RED')
        assert hasattr(Colors, 'GREEN')
        assert hasattr(Colors, 'RESET')


class TestProcessesModule:
    """Tests for utils.processes module."""

    @patch('psutil.net_connections')
    @patch('psutil.Process')
    def test_get_process_map(self, mock_process, mock_connections):
        """Test getting process map."""
        from utils.processes import get_process_map
        
        # Create mock connection
        mock_conn = Mock()
        mock_conn.laddr = Mock()
        mock_conn.laddr.ip = "127.0.0.1"
        mock_conn.laddr.port = 8080
        mock_conn.pid = 1234
        mock_connections.return_value = [mock_conn]
        
        # Create mock process
        mock_proc = Mock()
        mock_proc.name.return_value = "python"
        mock_process.return_value = mock_proc
        
        result = get_process_map()
        
        assert isinstance(result, dict)
