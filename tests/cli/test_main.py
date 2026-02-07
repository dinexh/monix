"""Tests for CLI main module."""

import pytest
from unittest.mock import patch, MagicMock
from click.testing import CliRunner
from cli.main import cli, main


class TestCliVersion:
    """Tests for CLI version command."""

    def test_version_flag(self):
        """Test --version flag."""
        runner = CliRunner()
        result = runner.invoke(cli, ['--version'])
        
        assert result.exit_code == 0
        assert 'monix v' in result.output

    def test_version_short_flag(self):
        """Test -v flag."""
        runner = CliRunner()
        result = runner.invoke(cli, ['-v'])
        
        assert result.exit_code == 0
        assert 'monix v' in result.output


class TestCliHelp:
    """Tests for CLI help command."""

    def test_no_command_shows_help(self):
        """Test that no command shows help."""
        runner = CliRunner()
        result = runner.invoke(cli, [])
        
        assert result.exit_code == 0
        # Help text should be displayed

    def test_help_flag(self):
        """Test --help flag."""
        runner = CliRunner()
        result = runner.invoke(cli, ['--help'])
        
        assert result.exit_code == 0
        assert 'Usage:' in result.output


class TestMonitorCommand:
    """Tests for monitor command."""

    @patch('cli.commands.monitor.run')
    def test_monitor_flag(self, mock_run):
        """Test --monitor flag."""
        runner = CliRunner()
        result = runner.invoke(cli, ['--monitor'])
        
        assert result.exit_code == 0
        mock_run.assert_called_once()

    @patch('cli.commands.monitor.run')
    def test_monitor_command(self, mock_run):
        """Test monitor subcommand."""
        runner = CliRunner()
        result = runner.invoke(cli, ['monitor'])
        
        assert result.exit_code == 0
        mock_run.assert_called_once()

    @patch('cli.commands.monitor.run')
    def test_monitor_with_json(self, mock_run):
        """Test monitor with --json flag."""
        runner = CliRunner()
        result = runner.invoke(cli, ['monitor', '--json'])
        
        assert result.exit_code == 0
        mock_run.assert_called_once_with(output_json=True)


class TestStatusCommand:
    """Tests for status command."""

    @patch('cli.commands.status.run')
    def test_status_flag(self, mock_run):
        """Test --status flag."""
        runner = CliRunner()
        result = runner.invoke(cli, ['--status'])
        
        assert result.exit_code == 0
        mock_run.assert_called_once()

    @patch('cli.commands.status.run')
    def test_status_command(self, mock_run):
        """Test status subcommand."""
        runner = CliRunner()
        result = runner.invoke(cli, ['status'])
        
        assert result.exit_code == 0
        mock_run.assert_called_once()


class TestWatchCommand:
    """Tests for watch command."""

    @patch('cli.commands.watch.run')
    def test_watch_flag(self, mock_run):
        """Test --watch flag."""
        runner = CliRunner()
        result = runner.invoke(cli, ['--watch'])
        
        assert result.exit_code == 0
        mock_run.assert_called_once()

    @patch('cli.commands.watch.run')
    def test_watch_command(self, mock_run):
        """Test watch subcommand."""
        runner = CliRunner()
        result = runner.invoke(cli, ['watch'])
        
        assert result.exit_code == 0
        mock_run.assert_called_once()

    @patch('cli.commands.watch.run')
    def test_watch_with_refresh(self, mock_run):
        """Test watch with custom refresh interval."""
        runner = CliRunner()
        result = runner.invoke(cli, ['watch', '--refresh', '5'])
        
        assert result.exit_code == 0
        mock_run.assert_called_once_with(refresh_interval=5)


class TestConnectionsCommand:
    """Tests for connections command."""

    @patch('cli.commands.connections.run')
    def test_connections_flag(self, mock_run):
        """Test --connections flag."""
        runner = CliRunner()
        result = runner.invoke(cli, ['--connections'])
        
        assert result.exit_code == 0
        mock_run.assert_called_once()

    @patch('cli.commands.connections.run')
    def test_connections_command(self, mock_run):
        """Test connections subcommand."""
        runner = CliRunner()
        result = runner.invoke(cli, ['connections'])
        
        assert result.exit_code == 0
        mock_run.assert_called_once()

    @patch('cli.commands.connections.run')
    def test_connections_with_state_filter(self, mock_run):
        """Test connections with state filter."""
        runner = CliRunner()
        result = runner.invoke(cli, ['connections', '--state', 'ESTABLISHED'])
        
        assert result.exit_code == 0
        mock_run.assert_called_once_with(
            state_filter='ESTABLISHED',
            limit=20,
            output_json=False
        )

    @patch('cli.commands.connections.run')
    def test_connections_with_limit(self, mock_run):
        """Test connections with custom limit."""
        runner = CliRunner()
        result = runner.invoke(cli, ['connections', '--limit', '50'])
        
        assert result.exit_code == 0
        mock_run.assert_called_once_with(
            state_filter=None,
            limit=50,
            output_json=False
        )


class TestAlertsCommand:
    """Tests for alerts command."""

    @patch('cli.commands.alerts.run')
    def test_alerts_flag(self, mock_run):
        """Test --alerts flag."""
        runner = CliRunner()
        result = runner.invoke(cli, ['--alerts'])
        
        assert result.exit_code == 0
        mock_run.assert_called_once()

    @patch('cli.commands.alerts.run')
    def test_alerts_command(self, mock_run):
        """Test alerts subcommand."""
        runner = CliRunner()
        result = runner.invoke(cli, ['alerts'])
        
        assert result.exit_code == 0
        mock_run.assert_called_once()

    @patch('cli.commands.alerts.run')
    def test_alerts_with_limit(self, mock_run):
        """Test alerts with custom limit."""
        runner = CliRunner()
        result = runner.invoke(cli, ['alerts', '--limit', '20'])
        
        assert result.exit_code == 0
        mock_run.assert_called_once_with(limit=20)


class TestScanCommand:
    """Tests for scan command."""

    @patch('cli.commands.scan.run')
    def test_scan_flag(self, mock_run):
        """Test --scan flag."""
        runner = CliRunner()
        result = runner.invoke(cli, ['--scan'])
        
        assert result.exit_code == 0
        mock_run.assert_called_once()

    @patch('cli.commands.scan.run')
    def test_scan_command(self, mock_run):
        """Test scan subcommand."""
        runner = CliRunner()
        result = runner.invoke(cli, ['scan'])
        
        assert result.exit_code == 0
        mock_run.assert_called_once()

    @patch('cli.commands.scan.run')
    def test_scan_with_deep(self, mock_run):
        """Test scan with --deep flag."""
        runner = CliRunner()
        result = runner.invoke(cli, ['scan', '--deep'])
        
        assert result.exit_code == 0
        mock_run.assert_called_once_with(deep=True)


class TestTrafficCommand:
    """Tests for traffic command."""

    @patch('cli.commands.traffic.run')
    def test_traffic_flag(self, mock_run):
        """Test --traffic flag."""
        runner = CliRunner()
        result = runner.invoke(cli, ['--traffic'])
        
        assert result.exit_code == 0
        mock_run.assert_called_once()

    @patch('cli.commands.traffic.run')
    def test_traffic_command(self, mock_run):
        """Test traffic subcommand."""
        runner = CliRunner()
        result = runner.invoke(cli, ['traffic'])
        
        assert result.exit_code == 0
        mock_run.assert_called_once()

    @patch('cli.commands.traffic.run')
    def test_traffic_with_custom_log(self, mock_run):
        """Test traffic with custom log path."""
        runner = CliRunner()
        result = runner.invoke(cli, ['traffic', '--log', '/custom/log.log'])
        
        assert result.exit_code == 0
        mock_run.assert_called_once()

    @patch('cli.commands.traffic.run')
    def test_traffic_with_window(self, mock_run):
        """Test traffic with custom time window."""
        runner = CliRunner()
        result = runner.invoke(cli, ['traffic', '--window', '30'])
        
        assert result.exit_code == 0
        mock_run.assert_called_once()


class TestWebCommand:
    """Tests for web command."""

    @patch('cli.commands.web.run_analysis')
    def test_web_command(self, mock_run):
        """Test web subcommand."""
        runner = CliRunner()
        result = runner.invoke(cli, ['web', 'https://example.com'])
        
        assert result.exit_code == 0
        mock_run.assert_called_once_with('https://example.com')
