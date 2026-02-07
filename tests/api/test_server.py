"""Tests for api.server module."""

import pytest
import json
from unittest.mock import patch, Mock


class TestHealthEndpoint:
    """Tests for /api/health endpoint."""

    def test_health_check(self, mock_flask_app):
        """Test health check endpoint returns ok status."""
        response = mock_flask_app.get("/api/health")
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data["status"] == "ok"
        assert data["service"] == "monix-api"


class TestAnalyzeUrlEndpoint:
    """Tests for /api/analyze-url endpoint."""

    @patch("api.server.analyze_web_security")
    def test_analyze_url_success(self, mock_analyze, mock_flask_app):
        """Test successful URL analysis."""
        mock_analyze.return_value = {
            "status": "success",
            "url": "https://example.com",
            "threat_score": 0,
        }
        
        response = mock_flask_app.post(
            "/api/analyze-url",
            data=json.dumps({"url": "https://example.com"}),
            content_type="application/json"
        )
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data["status"] == "success"
        assert data["url"] == "https://example.com"

    def test_analyze_url_missing_url(self, mock_flask_app):
        """Test error when URL is missing."""
        response = mock_flask_app.post(
            "/api/analyze-url",
            data=json.dumps({}),
            content_type="application/json"
        )
        
        assert response.status_code == 400
        data = json.loads(response.data)
        assert data["status"] == "error"
        assert "url" in data["error"].lower()

    def test_analyze_url_no_body(self, mock_flask_app):
        """Test error when request has no body."""
        response = mock_flask_app.post("/api/analyze-url")
        
        # Flask returns 415 (Unsupported Media Type) or 400 depending on version
        assert response.status_code in [400, 415]

    @patch("api.server.analyze_web_security")
    def test_analyze_url_with_full_scan(self, mock_analyze, mock_flask_app):
        """Test URL analysis with full scan parameter."""
        mock_analyze.return_value = {"status": "success"}
        
        response = mock_flask_app.post(
            "/api/analyze-url?full=true",
            data=json.dumps({"url": "https://example.com"}),
            content_type="application/json"
        )
        
        assert response.status_code == 200
        # Verify full scan parameters were passed
        mock_analyze.assert_called_once_with(
            "https://example.com",
            include_port_scan=True,
            include_metadata=True
        )

    @patch("api.server.analyze_web_security")
    def test_analyze_url_exception(self, mock_analyze, mock_flask_app):
        """Test handling of exceptions during analysis."""
        mock_analyze.side_effect = Exception("Analysis failed")
        
        response = mock_flask_app.post(
            "/api/analyze-url",
            data=json.dumps({"url": "https://example.com"}),
            content_type="application/json"
        )
        
        assert response.status_code == 500
        data = json.loads(response.data)
        assert data["status"] == "error"


class TestAnalyzeIpEndpoint:
    """Tests for /api/analyze-ip endpoint."""

    @patch("api.server.get_ip_info")
    def test_analyze_ip_success(self, mock_get_ip_info, mock_flask_app):
        """Test successful IP analysis."""
        mock_get_ip_info.return_value = {
            "geo": "San Francisco, US",
            "hostname": "example.com"
        }
        
        response = mock_flask_app.post(
            "/api/analyze-ip",
            data=json.dumps({"ip": "8.8.8.8"}),
            content_type="application/json"
        )
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data["status"] == "success"
        assert data["ip"] == "8.8.8.8"
        assert data["geo_info"] == "San Francisco, US"
        assert data["hostname"] == "example.com"

    def test_analyze_ip_missing_ip(self, mock_flask_app):
        """Test error when IP is missing."""
        response = mock_flask_app.post(
            "/api/analyze-ip",
            data=json.dumps({}),
            content_type="application/json"
        )
        
        assert response.status_code == 400
        data = json.loads(response.data)
        assert data["status"] == "error"


class TestThreatInfoEndpoint:
    """Tests for /api/threat-info endpoint."""

    def test_threat_info(self, mock_flask_app):
        """Test threat info endpoint returns pattern information."""
        response = mock_flask_app.get("/api/threat-info")
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data["status"] == "success"
        assert "high_risk_endpoints" in data
        assert "malicious_bot_signatures" in data
        assert len(data["high_risk_endpoints"]) > 0
        assert len(data["malicious_bot_signatures"]) > 0


class TestConnectionsEndpoint:
    """Tests for /api/connections endpoint."""

    @patch("api.server.collect_connections")
    def test_connections_success(self, mock_collect, mock_flask_app):
        """Test successful connections retrieval."""
        mock_collect.return_value = [
            {"local": "0.0.0.0:80", "remote": "*:*", "status": "LISTEN"}
        ]
        
        response = mock_flask_app.get("/api/connections")
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data["status"] == "success"
        assert "connections" in data
        assert data["count"] == 1

    @patch("api.server.collect_connections")
    def test_connections_error(self, mock_collect, mock_flask_app):
        """Test error handling in connections endpoint."""
        mock_collect.side_effect = Exception("Connection error")
        
        response = mock_flask_app.get("/api/connections")
        
        assert response.status_code == 500
        data = json.loads(response.data)
        assert data["status"] == "error"


class TestAlertsEndpoint:
    """Tests for /api/alerts endpoint."""

    @patch("api.server.state")
    def test_alerts_success(self, mock_state, mock_flask_app):
        """Test successful alerts retrieval."""
        mock_state.snapshot.return_value = (None, [
            {"type": "high_cpu", "severity": "warning"}
        ])
        
        response = mock_flask_app.get("/api/alerts")
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data["status"] == "success"
        assert "alerts" in data
        assert data["count"] == 1

    @patch("api.server.state")
    def test_alerts_error(self, mock_state, mock_flask_app):
        """Test error handling in alerts endpoint."""
        mock_state.snapshot.side_effect = Exception("State error")
        
        response = mock_flask_app.get("/api/alerts")
        
        assert response.status_code == 500
        data = json.loads(response.data)
        assert data["status"] == "error"


class TestSystemStatsEndpoint:
    """Tests for /api/system-stats endpoint."""

    @patch("api.server.get_system_stats")
    def test_system_stats_success(self, mock_get_stats, mock_flask_app):
        """Test successful system stats retrieval."""
        mock_get_stats.return_value = {
            "cpu_percent": 45.5,
            "memory_percent": 60.2
        }
        
        response = mock_flask_app.get("/api/system-stats")
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data["status"] == "success"
        assert data["cpu_percent"] == 45.5
        assert data["memory_percent"] == 60.2

    @patch("api.server.get_system_stats")
    def test_system_stats_error(self, mock_get_stats, mock_flask_app):
        """Test error handling in system stats endpoint."""
        mock_get_stats.side_effect = Exception("Stats error")
        
        response = mock_flask_app.get("/api/system-stats")
        
        assert response.status_code == 500


class TestProcessesEndpoint:
    """Tests for /api/processes endpoint."""

    @patch("api.server.get_top_processes")
    def test_processes_success(self, mock_get_processes, mock_flask_app):
        """Test successful processes retrieval."""
        mock_get_processes.return_value = [
            {"pid": 1234, "name": "python", "cpu": 45.5}
        ]
        
        response = mock_flask_app.get("/api/processes")
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data["status"] == "success"
        assert len(data["processes"]) == 1
        assert data["count"] == 1

    @patch("api.server.get_top_processes")
    def test_processes_with_limit(self, mock_get_processes, mock_flask_app):
        """Test processes endpoint with custom limit."""
        mock_get_processes.return_value = []
        
        response = mock_flask_app.get("/api/processes?limit=5")
        
        assert response.status_code == 200
        mock_get_processes.assert_called_once_with(limit=5)

    @patch("api.server.get_top_processes")
    def test_processes_error(self, mock_get_processes, mock_flask_app):
        """Test error handling in processes endpoint."""
        mock_get_processes.side_effect = Exception("Process error")
        
        response = mock_flask_app.get("/api/processes")
        
        assert response.status_code == 500


class TestDashboardEndpoint:
    """Tests for /api/dashboard endpoint."""

    @patch("api.server.get_traffic_summary")
    @patch("api.server.get_system_stats")
    @patch("api.server.state")
    @patch("api.server.collect_connections")
    def test_dashboard_success(
        self,
        mock_collect,
        mock_state,
        mock_stats,
        mock_traffic,
        mock_flask_app
    ):
        """Test successful dashboard data retrieval."""
        mock_collect.return_value = []
        mock_state.snapshot.return_value = (None, [])
        mock_stats.return_value = {"cpu_percent": 50.0}
        mock_traffic.return_value = {
            "total_requests": 100,
            "unique_ips": 20,
            "total_404s": 5,
            "high_risk_hits": 2,
            "suspicious_ips": []
        }
        
        response = mock_flask_app.get("/api/dashboard")
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data["status"] == "success"
        assert "connections" in data
        assert "alerts" in data
        assert "system_stats" in data
        assert "traffic_summary" in data

    @patch("api.server.collect_connections")
    def test_dashboard_error(self, mock_collect, mock_flask_app):
        """Test error handling in dashboard endpoint."""
        mock_collect.side_effect = Exception("Dashboard error")
        
        response = mock_flask_app.get("/api/dashboard")
        
        assert response.status_code == 500
