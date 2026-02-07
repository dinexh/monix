"""Tests for core.analyzers.traffic module."""

import pytest
from datetime import datetime, timedelta
from core.analyzers.traffic import (
    parse_log_line,
    LogEntry,
    is_suspicious_url,
    is_malicious_bot,
    analyze_traffic,
    classify_threat_level,
    HIGH_RISK_ENDPOINTS,
    MALICIOUS_BOT_SIGNATURES,
)


class TestParseLogLine:
    """Tests for parse_log_line function."""

    def test_parse_valid_log_line(self, sample_nginx_log_line):
        """Test parsing a valid Nginx log line."""
        entry = parse_log_line(sample_nginx_log_line)
        
        assert entry is not None
        assert entry.ip == "192.168.1.100"
        assert entry.method == "GET"
        assert entry.url == "/test"
        assert entry.status == 200
        assert entry.size == 1234
        assert entry.user_agent == "Mozilla/5.0"
        assert isinstance(entry.timestamp, datetime)

    def test_parse_suspicious_log_line(self, sample_suspicious_log_line):
        """Test parsing a suspicious log line."""
        entry = parse_log_line(sample_suspicious_log_line)
        
        assert entry is not None
        assert entry.ip == "203.0.113.50"
        assert entry.url == "/wp-login.php"
        assert entry.status == 404
        assert entry.user_agent == "sqlmap/1.0"

    def test_parse_invalid_log_line(self):
        """Test parsing an invalid log line."""
        entry = parse_log_line("invalid log line")
        assert entry is None

    def test_parse_empty_log_line(self):
        """Test parsing an empty log line."""
        entry = parse_log_line("")
        assert entry is None


class TestIsSuspiciousUrl:
    """Tests for is_suspicious_url function."""

    def test_suspicious_urls(self):
        """Test detection of suspicious URLs."""
        suspicious_urls = [
            "/wp-login.php",
            "/admin",
            "/.env",
            "/phpmyadmin",
            "/shell",
        ]
        
        for url in suspicious_urls:
            assert is_suspicious_url(url), f"{url} should be flagged as suspicious"

    def test_normal_urls(self):
        """Test that normal URLs are not flagged."""
        normal_urls = [
            "/",
            "/about",
            "/contact",
            "/api/users",
            "/blog/post-1",
        ]
        
        for url in normal_urls:
            assert not is_suspicious_url(url), f"{url} should not be flagged"

    def test_case_insensitive_detection(self):
        """Test case-insensitive URL detection."""
        assert is_suspicious_url("/WP-LOGIN.PHP")
        assert is_suspicious_url("/Admin")
        assert is_suspicious_url("/.ENV")


class TestIsMaliciousBot:
    """Tests for is_malicious_bot function."""

    def test_malicious_bots(self):
        """Test detection of malicious bot user agents."""
        malicious_agents = [
            "sqlmap/1.0",
            "nikto",
            "python-requests/2.28",
            "curl/7.68",
            "Shodan/1.0",
        ]
        
        for agent in malicious_agents:
            assert is_malicious_bot(agent), f"{agent} should be flagged as malicious"

    def test_legitimate_user_agents(self):
        """Test that legitimate user agents are not flagged."""
        legitimate_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Chrome/91.0.4472.124 Safari/537.36",
            "Googlebot/2.1",
        ]
        
        for agent in legitimate_agents:
            assert not is_malicious_bot(agent), f"{agent} should not be flagged"

    def test_case_insensitive_bot_detection(self):
        """Test case-insensitive bot detection."""
        assert is_malicious_bot("SQLMAP/1.0")
        assert is_malicious_bot("Nikto")
        assert is_malicious_bot("PYTHON-REQUESTS")


class TestAnalyzeTraffic:
    """Tests for analyze_traffic function."""

    def test_analyze_empty_entries(self):
        """Test analyzing empty log entries."""
        result = analyze_traffic([])
        assert result == []

    def test_analyze_normal_traffic(self):
        """Test analyzing normal traffic patterns."""
        base_time = datetime.utcnow()
        entries = [
            LogEntry("192.168.1.100", base_time, "GET", "/", 200, "Mozilla/5.0", 1234)
            for _ in range(5)
        ]
        
        result = analyze_traffic(entries, high_rate_threshold=30)
        # Normal traffic shouldn't trigger alerts
        assert len(result) == 0

    def test_analyze_high_rate_traffic(self):
        """Test detection of high-rate traffic."""
        base_time = datetime.utcnow()
        entries = [
            LogEntry(
                "192.168.1.100",
                base_time - timedelta(seconds=i),
                "GET",
                "/",
                200,
                "Mozilla/5.0",
                1234
            )
            for i in range(35)
        ]
        
        result = analyze_traffic(entries, high_rate_threshold=30)
        assert len(result) == 1
        assert result[0].ip == "192.168.1.100"
        assert result[0].high_rate is True
        assert result[0].threat_score > 0

    def test_analyze_suspicious_url_access(self):
        """Test detection of suspicious URL access."""
        base_time = datetime.utcnow()
        entries = [
            LogEntry(
                "203.0.113.50",
                base_time,
                "GET",
                "/wp-login.php",
                404,
                "Mozilla/5.0",
                0
            )
        ]
        
        result = analyze_traffic(entries)
        assert len(result) == 1
        assert result[0].ip == "203.0.113.50"
        assert len(result[0].suspicious_urls) > 0
        assert result[0].threat_score > 0

    def test_analyze_malicious_bot(self):
        """Test detection of malicious bot activity."""
        base_time = datetime.utcnow()
        entries = [
            LogEntry(
                "203.0.113.100",
                base_time,
                "GET",
                "/",
                200,
                "sqlmap/1.0",
                100
            )
        ]
        
        result = analyze_traffic(entries)
        assert len(result) == 1
        assert result[0].ip == "203.0.113.100"
        assert result[0].malicious_bot is True
        assert result[0].threat_score >= 30

    def test_analyze_multiple_404s(self):
        """Test detection of repeated 404 attempts."""
        base_time = datetime.utcnow()
        entries = [
            LogEntry(
                "203.0.113.75",
                base_time - timedelta(seconds=i),
                "GET",
                f"/test{i}",
                404,
                "Mozilla/5.0",
                0
            )
            for i in range(10)
        ]
        
        result = analyze_traffic(entries)
        assert len(result) == 1
        assert result[0].ip == "203.0.113.75"
        assert result[0].status_404_count == 10
        assert result[0].threat_score > 15


class TestClassifyThreatLevel:
    """Tests for classify_threat_level function."""

    def test_critical_threat_level(self):
        """Test classification of critical threat level."""
        level, color = classify_threat_level(50)
        assert level == "CRITICAL"
        assert color == "red"

    def test_high_threat_level(self):
        """Test classification of high threat level."""
        level, color = classify_threat_level(35)
        assert level == "HIGH"
        assert color == "yellow"

    def test_medium_threat_level(self):
        """Test classification of medium threat level."""
        level, color = classify_threat_level(20)
        assert level == "MEDIUM"
        assert color == "cyan"

    def test_low_threat_level(self):
        """Test classification of low threat level."""
        level, color = classify_threat_level(5)
        assert level == "LOW"
        assert color == "white"

    def test_zero_threat_level(self):
        """Test classification of zero threat level."""
        level, color = classify_threat_level(0)
        assert level == "LOW"
        assert color == "white"


class TestHighRiskEndpoints:
    """Tests for HIGH_RISK_ENDPOINTS list."""

    def test_high_risk_endpoints_exist(self):
        """Test that high-risk endpoints are defined."""
        assert len(HIGH_RISK_ENDPOINTS) > 0

    def test_common_attack_targets_included(self):
        """Test that common attack targets are in the list."""
        common_targets = [
            "/wp-login.php",
            "/admin",
            "/.env",
            "/phpmyadmin",
        ]
        
        for target in common_targets:
            assert target in HIGH_RISK_ENDPOINTS


class TestMaliciousBotSignatures:
    """Tests for MALICIOUS_BOT_SIGNATURES list."""

    def test_malicious_bot_signatures_exist(self):
        """Test that malicious bot signatures are defined."""
        assert len(MALICIOUS_BOT_SIGNATURES) > 0

    def test_common_scanners_included(self):
        """Test that common scanning tools are in the list."""
        common_scanners = [
            "sqlmap",
            "nikto",
            "nmap",
        ]
        
        for scanner in common_scanners:
            assert scanner in MALICIOUS_BOT_SIGNATURES
