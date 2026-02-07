# Testing Guide

This document provides information about the Monix testing suite.

## Test Structure

The test suite is organized to mirror the application structure:

```
tests/
├── conftest.py              # Shared fixtures and configuration
├── core/                    # Tests for core modules
│   ├── test_traffic.py      # Traffic analyzer tests
│   └── test_system.py       # System collector tests
├── utils/                   # Tests for utility modules
│   ├── test_geo.py          # Geolocation tests
│   └── test_utils.py        # General utility tests
├── api/                     # Tests for API endpoints
│   └── test_server.py       # API server tests
└── cli/                     # Tests for CLI commands
    └── test_main.py         # CLI interface tests
```

## Running Tests

### Prerequisites

Install test dependencies:

```bash
pip install -e ".[dev]"
```

Or install manually:

```bash
pip install pytest pytest-cov pytest-mock
```

### Run All Tests

```bash
pytest tests/
```

### Run Specific Test Files

```bash
# Test traffic analyzer
pytest tests/core/test_traffic.py

# Test API endpoints
pytest tests/api/test_server.py

# Test CLI commands
pytest tests/cli/test_main.py
```

### Run Tests with Verbose Output

```bash
pytest tests/ -v
```

### Run Tests with Coverage

```bash
pytest tests/ --cov=. --cov-report=html --cov-report=term
```

This will generate a coverage report in `htmlcov/index.html`.

### Run Specific Test Classes or Methods

```bash
# Run a specific test class
pytest tests/core/test_traffic.py::TestParseLogLine

# Run a specific test method
pytest tests/core/test_traffic.py::TestParseLogLine::test_parse_valid_log_line
```

## Test Categories

### Unit Tests

Unit tests verify individual functions and methods in isolation:

- **core/test_traffic.py**: Tests for log parsing, traffic analysis, threat detection
- **core/test_system.py**: Tests for system statistics collection
- **utils/test_geo.py**: Tests for geolocation and DNS lookups
- **utils/test_utils.py**: Tests for utility functions

### Integration Tests

Integration tests verify that different components work together:

- **api/test_server.py**: Tests for Flask API endpoints with mocked dependencies

### CLI Tests

CLI tests verify command-line interface functionality:

- **cli/test_main.py**: Tests for CLI commands and argument parsing

## Writing Tests

### Test Naming Convention

- Test files: `test_*.py`
- Test classes: `Test*`
- Test methods: `test_*`

### Using Fixtures

Fixtures are defined in `conftest.py` and can be used in any test:

```python
def test_something(mock_log_entries):
    # mock_log_entries is available from conftest.py
    assert len(mock_log_entries) > 0
```

### Mocking External Dependencies

Use `unittest.mock` or `pytest-mock` to mock external dependencies:

```python
from unittest.mock import patch

@patch('requests.get')
def test_api_call(mock_get):
    mock_get.return_value.json.return_value = {"status": "ok"}
    # Test code here
```

## Continuous Integration

Tests are automatically run on:
- Every push to `main` or `develop` branches
- Every pull request to `main` or `develop` branches

The CI workflow runs tests on Python versions 3.8, 3.9, 3.10, 3.11, and 3.12.

## Coverage Goals

We aim for:
- **Overall coverage**: 80%+
- **Core modules**: 90%+
- **Critical security functions**: 95%+

Check current coverage:

```bash
pytest tests/ --cov=. --cov-report=term-missing
```

## Best Practices

1. **Write tests first**: Consider writing tests before implementing features (TDD)
2. **Test edge cases**: Don't just test the happy path
3. **Keep tests independent**: Tests should not depend on each other
4. **Use descriptive names**: Test names should clearly describe what they test
5. **Mock external services**: Don't make real API calls or network requests in tests
6. **Test error handling**: Verify that errors are handled gracefully

## Common Issues

### Import Errors

If you get import errors, make sure you've installed the package in development mode:

```bash
pip install -e .
```

### Permission Errors

Some tests may require specific permissions (e.g., reading system logs). These tests should gracefully handle permission errors.

### Platform-Specific Tests

Some functionality is Linux-specific. Tests should skip or adapt for other platforms:

```python
import platform
import pytest

@pytest.mark.skipif(platform.system() != 'Linux', reason="Linux-only test")
def test_linux_feature():
    # Test code here
```

## Contributing

When adding new features:

1. Write tests for the new functionality
2. Ensure all tests pass: `pytest tests/`
3. Check test coverage: `pytest tests/ --cov=.`
4. Update this documentation if needed

## Resources

- [pytest documentation](https://docs.pytest.org/)
- [pytest-cov documentation](https://pytest-cov.readthedocs.io/)
- [unittest.mock documentation](https://docs.python.org/3/library/unittest.mock.html)
