"""Tests for utils.geo module."""

import pytest
from unittest.mock import patch, Mock
from utils.geo import (
    reverse_dns,
    geo_lookup,
    get_my_location,
    get_ip_info,
)


class TestReverseDns:
    """Tests for reverse_dns function."""

    def test_localhost_returns_empty(self):
        """Test that localhost addresses return empty string."""
        assert reverse_dns("127.0.0.1") == ""
        assert reverse_dns("0.0.0.0") == ""
        assert reverse_dns("::1") == ""
        assert reverse_dns("::") == ""

    @patch("socket.gethostbyaddr")
    def test_valid_ip_lookup(self, mock_gethostbyaddr):
        """Test successful reverse DNS lookup."""
        mock_gethostbyaddr.return_value = ("example.com", [], ["192.168.1.1"])
        
        result = reverse_dns("192.168.1.1")
        assert result == "example.com"
        mock_gethostbyaddr.assert_called_once_with("192.168.1.1")

    @patch("socket.gethostbyaddr")
    def test_failed_lookup(self, mock_gethostbyaddr):
        """Test failed reverse DNS lookup."""
        # Clear cache for this test
        from utils.geo import _dns_cache
        test_ip = "192.168.99.99"
        _dns_cache.pop(test_ip, None)
        
        mock_gethostbyaddr.side_effect = Exception("Lookup failed")
        
        result = reverse_dns(test_ip)
        assert result == ""

    @patch("socket.gethostbyaddr")
    def test_caching(self, mock_gethostbyaddr):
        """Test that results are cached."""
        # Clear cache for this test
        from utils.geo import _dns_cache
        test_ip = "192.168.1.2"
        _dns_cache.pop(test_ip, None)
        
        mock_gethostbyaddr.return_value = ("example.com", [], [test_ip])
        
        # First call
        result1 = reverse_dns(test_ip)
        # Second call should use cache
        result2 = reverse_dns(test_ip)
        
        # Should only call once due to caching
        assert mock_gethostbyaddr.call_count == 1


class TestGeoLookup:
    """Tests for geo_lookup function."""

    def test_localhost_returns_empty(self):
        """Test that localhost addresses return empty string."""
        assert geo_lookup("127.0.0.1") == ""
        assert geo_lookup("127.0.0.5") == ""

    def test_empty_ip_returns_empty(self):
        """Test that empty IP returns empty string."""
        assert geo_lookup("") == ""
        assert geo_lookup(None) == ""

    @patch("requests.get")
    def test_successful_geo_lookup(self, mock_get):
        """Test successful geolocation lookup."""
        mock_response = Mock()
        mock_response.json.return_value = {
            "city": "San Francisco",
            "country": "US",
            "org": "Example ISP"
        }
        mock_get.return_value = mock_response
        
        result = geo_lookup("8.8.8.8")
        assert "San Francisco" in result
        assert "US" in result
        assert "Example ISP" in result

    @patch("requests.get")
    def test_geo_lookup_without_city(self, mock_get):
        """Test geolocation lookup without city info."""
        mock_response = Mock()
        mock_response.json.return_value = {
            "country": "US",
            "org": "Example ISP"
        }
        mock_get.return_value = mock_response
        
        result = geo_lookup("8.8.8.8")
        assert "US" in result
        assert "Example ISP" in result

    @patch("requests.get")
    def test_failed_geo_lookup(self, mock_get):
        """Test failed geolocation lookup."""
        # Clear cache for this test
        from utils.geo import _geo_cache
        test_ip = "8.8.8.99"
        _geo_cache.pop(test_ip, None)
        
        mock_get.side_effect = Exception("Lookup failed")
        
        result = geo_lookup(test_ip)
        assert result == ""

    @patch("requests.get")
    def test_geo_lookup_caching(self, mock_get):
        """Test that geolocation results are cached."""
        # Clear cache for this test
        from utils.geo import _geo_cache
        test_ip = "1.2.3.4"
        _geo_cache.pop(test_ip, None)
        
        mock_response = Mock()
        mock_response.json.return_value = {
            "city": "New York",
            "country": "US"
        }
        mock_get.return_value = mock_response
        
        # First call
        result1 = geo_lookup(test_ip)
        # Second call should use cache
        result2 = geo_lookup(test_ip)
        
        # Should only call once due to caching
        assert mock_get.call_count == 1


class TestGetMyLocation:
    """Tests for get_my_location function."""

    @patch("requests.get")
    def test_successful_location_lookup(self, mock_get):
        """Test successful location lookup."""
        mock_response = Mock()
        mock_response.json.return_value = {
            "city": "Seattle",
            "country": "US"
        }
        mock_get.return_value = mock_response
        
        result = get_my_location()
        assert "Seattle" in result
        assert "US" in result

    @patch("requests.get")
    def test_failed_location_lookup(self, mock_get):
        """Test failed location lookup."""
        # Clear cache for this test
        from utils.geo import _location_cache
        _location_cache.pop("self", None)
        
        mock_get.side_effect = Exception("Lookup failed")
        
        result = get_my_location()
        assert result == "Unknown Location"

    @patch("requests.get")
    def test_location_caching(self, mock_get):
        """Test that location results are cached."""
        # Clear cache for this test
        from utils.geo import _location_cache
        _location_cache.pop("self", None)
        
        mock_response = Mock()
        mock_response.json.return_value = {
            "city": "Boston",
            "country": "US"
        }
        mock_get.return_value = mock_response
        
        # Multiple calls
        result1 = get_my_location()
        result2 = get_my_location()
        
        # Should only call once due to caching
        assert mock_get.call_count == 1


class TestGetIpInfo:
    """Tests for get_ip_info function."""

    @patch("utils.geo.geo_lookup")
    @patch("utils.geo.reverse_dns")
    def test_get_ip_info(self, mock_reverse_dns, mock_geo_lookup):
        """Test getting IP information."""
        mock_geo_lookup.return_value = "San Francisco, US | Example ISP"
        mock_reverse_dns.return_value = "example.com"
        
        result = get_ip_info("8.8.8.8")
        
        assert result["ip"] == "8.8.8.8"
        assert result["geo"] == "San Francisco, US | Example ISP"
        assert result["hostname"] == "example.com"

    @patch("utils.geo.geo_lookup")
    @patch("utils.geo.reverse_dns")
    def test_get_ip_info_with_failures(self, mock_reverse_dns, mock_geo_lookup):
        """Test getting IP information with lookup failures."""
        mock_geo_lookup.return_value = ""
        mock_reverse_dns.return_value = ""
        
        result = get_ip_info("192.168.1.1")
        
        assert result["ip"] == "192.168.1.1"
        assert result["geo"] == ""
        assert result["hostname"] == ""
