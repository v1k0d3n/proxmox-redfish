# Contributor Guide - Development and Testing

This guide is for developers who want to contribute to the Proxmox Redfish Daemon project. It covers development environment setup, code structure, testing, and contribution workflow.

## Development Environment Setup

### Prerequisites

- Python 3.8 or higher
- Git
- Virtual environment tools
- Proxmox VE test environment (optional)

### Quick Setup

```bash
# Clone the repository
git clone https://github.com/v1k0d3n/proxmox-redfish.git
cd proxmox-redfish

# Run the development setup script
./scripts/dev-setup.sh
```

### Manual Setup

```bash
# Clone the repository
git clone https://github.com/v1k0d3n/proxmox-redfish.git
cd proxmox-redfish

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Upgrade pip
pip install --upgrade pip

# Install dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt

# Install the package in editable mode
pip install -e .

# Install pre-commit hooks
pre-commit install
```

## Code Structure

```
proxmox-redfish/
├── src/
│   └── proxmox_redfish/
│       └── proxmox_redfish.py      # Main daemon implementation
├── tests/
│   ├── unit/                       # Unit tests
│   │   ├── test_proxmox_redfish.py
│   │   └── test_proxmox_redfish_simple.py
│   └── integration/                # Integration tests
│       └── test_real_vm_concurrent_iso.py
├── scripts/                        # Utility scripts
│   ├── install.sh
│   ├── setup_ssl.sh
│   └── dev-setup.sh
├── config/                         # Configuration examples
│   ├── ssl/
│   ├── params.env.example
│   └── proxmox-redfish.service.example
├── docs/                           # Documentation
├── requirements.txt                # Runtime dependencies
├── requirements-dev.txt            # Development dependencies
├── pyproject.toml                  # Project configuration
└── setup.py                        # Package setup
```

### Key Components

#### Main Daemon (`src/proxmox_redfish/proxmox_redfish.py`)

- **RedfishRequestHandler**: HTTP request handler for Redfish API
- **Power Management Functions**: `power_on()`, `power_off()`, `reboot()`, `reset_vm()`
- **Virtual Media Functions**: `manage_virtual_media()`, `get_virtual_media()`
- **System Information Functions**: `get_vm_status()`, `get_bios()`
- **Authentication**: `validate_token()`, session management
- **Error Handling**: `handle_proxmox_error()`

#### Configuration Management

- Environment variable support
- JSON configuration file support
- SSL certificate management
- Logging configuration

## Testing

### Running Tests

```bash
# Activate virtual environment
source venv/bin/activate

# Run all tests
pytest tests/ -v

# Run unit tests only
pytest tests/unit/ -v

# Run integration tests only
pytest tests/integration/ -v

# Run tests with coverage
pytest tests/ --cov=src/proxmox_redfish --cov-report=html

# Run specific test file
pytest tests/unit/test_proxmox_redfish.py -v

# Run specific test function
pytest tests/unit/test_proxmox_redfish.py::TestRedfishProxmox::test_power_on_success -v
```

### Test Categories

#### Unit Tests (`tests/unit/`)

- **Mock-based tests**: Test individual functions with mocked dependencies
- **Fast execution**: No external dependencies required
- **Isolated testing**: Each test is independent

```bash
# Run unit tests
pytest tests/unit/ -v
```

#### Integration Tests (`tests/integration/`)

- **Real VM tests**: Test against actual Proxmox VMs
- **Concurrent operations**: Test thread safety
- **End-to-end workflows**: Test complete Redfish operations

```bash
# Run integration tests (requires REAL_VM_TESTS=1)
REAL_VM_TESTS=1 pytest tests/integration/ -v
```

### Test Configuration

The test configuration is defined in `pyproject.toml`:

```toml
[tool.pytest.ini_options]
minversion = "6.0"
addopts = "-ra -q --strict-markers --strict-config"
testpaths = ["tests"]
python_files = ["test_*.py", "*_test.py"]
python_classes = ["Test*"]
python_functions = ["test_*"]
markers = [
    "slow: marks tests as slow (deselect with '-m \"not slow\"')",
    "integration: marks tests as integration tests",
    "unit: marks tests as unit tests",
]
```

### Writing Tests

#### Unit Test Example

```python
def test_power_on_success(self):
    """Test successful power on operation"""
    mock_proxmox = self.create_mock_proxmox()
    
    response, status_code = power_on(mock_proxmox, self.test_vm_id)
    
    self.assertEqual(status_code, 202)
    self.assertIn("@odata.id", response)
    self.assertEqual(response["TaskState"], "Running")
    
    # Verify Proxmox API was called
    mock_proxmox.nodes.return_value.qemu.return_value.status.start.post.assert_called_once()
```

#### Integration Test Example

```python
@skip_if_no_real_vms
def test_virtual_media_insert(vm_id):
    """Test VirtualMedia insert operation."""
    try:
        url = f"{REDFISH_BASE_URL}/redfish/v1/Managers/{vm_id}/VirtualMedia/Cd/Actions/VirtualMedia.InsertMedia"
        data = {"Image": "https://example.com/test.iso"}
        response = requests.post(url, headers=HEADERS, json=data, timeout=30)
        
        if response.status_code == 202:
            log(f"VirtualMedia insert successful: {response.json()}", vm_id)
            return True, response.json()
        else:
            log(f"VirtualMedia insert failed: {response.status_code}", vm_id)
            return False, None
            
    except Exception as e:
        log(f"VirtualMedia insert error: {e}", vm_id)
        return False, None
```

## Code Quality Tools

### Linting and Formatting

```bash
# Format code with Black
black src/ tests/

# Sort imports with isort
isort src/ tests/

# Check code formatting
black --check src/ tests/
isort --check-only src/ tests/

# Run all formatting tools
pre-commit run --all-files
```

### Linting with Flake8

```bash
# Run flake8 linting
flake8 src/ tests/

# Configuration is in pyproject.toml:
# [tool.flake8]
# max-line-length = 120
# ignore = ["E203", "E501", "W503"]
```

### Type Checking with MyPy

```bash
# Run type checking
mypy src/

# Configuration is in pyproject.toml:
# [tool.mypy]
# python_version = "3.8"
# warn_return_any = true
# disallow_untyped_defs = true
# warn_unreachable = false
```

### Security Scanning with Bandit

```bash
# Run security scan
bandit -r src/

# Run with specific confidence and severity levels
bandit -r src/ -f json -o bandit-report.json
```

### Pre-commit Hooks

The project uses pre-commit hooks to ensure code quality:

```bash
# Install pre-commit hooks
pre-commit install

# Run all hooks on staged files
pre-commit run

# Run all hooks on all files
pre-commit run --all-files

# Update hooks to latest versions
pre-commit autoupdate
```

## Code Style Guidelines

### Python Style

- Follow [PEP 8](https://www.python.org/dev/peps/pep-0008/) style guide
- Use Black for code formatting (line length: 120)
- Use isort for import sorting
- Add type hints to all functions
- Use f-strings for string formatting
- Use descriptive variable and function names

### Documentation

- Use docstrings for all functions and classes
- Follow Google docstring format
- Include examples in docstrings
- Update README files when adding features

### Error Handling

- Use specific exception types
- Provide meaningful error messages
- Log errors with appropriate levels
- Return consistent error response formats

### Testing

- Write tests for all new functionality
- Use descriptive test names
- Mock external dependencies
- Test both success and failure cases
- Maintain high test coverage

## Development Workflow

### 1. Fork and Clone

```bash
# Fork the repository on GitHub
# Clone your fork
git clone https://github.com/your-username/proxmox-redfish.git
cd proxmox-redfish

# Add upstream remote
git remote add upstream https://github.com/v1k0d3n/proxmox-redfish.git
```

### 2. Create Feature Branch

```bash
# Update main branch
git checkout main
git pull upstream main

# Create feature branch
git checkout -b feature/your-feature-name
```

### 3. Make Changes

```bash
# Make your changes
# Write tests for new functionality
# Update documentation

# Run tests
pytest tests/ -v

# Run linting
pre-commit run --all-files
```

### 4. Commit Changes

```bash
# Stage changes
git add .

# Commit with descriptive message
git commit -m "feat: add new Redfish endpoint for system inventory

- Add GET /redfish/v1/Systems/{id}/Inventory endpoint
- Implement inventory collection from Proxmox
- Add unit tests for inventory functionality
- Update documentation with new endpoint

Closes #123"
```

### 5. Push and Create Pull Request

```bash
# Push to your fork
git push origin feature/your-feature-name

# Create pull request on GitHub
# Include:
# - Description of changes
# - Test results
# - Screenshots (if UI changes)
# - Related issue number
```

### Commit Message Format

Use conventional commit format:

```
type(scope): description

[optional body]

[optional footer]
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes
- `refactor`: Code refactoring
- `test`: Test changes
- `chore`: Maintenance tasks

## Building and Packaging

### Local Development Build

```bash
# Install in editable mode
pip install -e .

# Test the installation
proxmox-redfish --help
```

### Package Distribution

```bash
# Build package
python -m build

# Check package
twine check dist/*

# Upload to PyPI (if you have access)
twine upload dist/*
```

### Docker Build

```bash
# Build Docker image
docker build -t proxmox-redfish .

# Run Docker container
docker run -d \
  --name proxmox-redfish-dev \
  -p 8443:8443 \
  -e PROXMOX_HOST=your-host \
  -e PROXMOX_USER=your-user \
  -e PROXMOX_PASSWORD=your-password \
  proxmox-redfish
```

## Debugging

### Local Development Server

```bash
# Run daemon in development mode
python src/proxmox_redfish/proxmox_redfish.py --port 8443 --log-level DEBUG

# Test with curl
curl -k -u "user:pass" https://localhost:8443/redfish/v1/
```

### Debug Configuration

```bash
# Set debug environment variables
export REDFISH_LOG_LEVEL=DEBUG
export REDFISH_LOGGING_ENABLED=true

# Run with debug logging
python src/proxmox_redfish/proxmox_redfish.py --log-level DEBUG
```

### Using Python Debugger

```python
import pdb; pdb.set_trace()  # Add this line where you want to break

# Or use ipdb for better experience
import ipdb; ipdb.set_trace()
```

## Performance Testing

### Load Testing

```bash
# Install load testing tools
pip install locust

# Create load test script
cat > load_test.py << 'EOF'
from locust import HttpUser, task, between

class RedfishUser(HttpUser):
    wait_time = between(1, 3)
    
    @task
    def get_systems(self):
        self.client.get("/redfish/v1/Systems", auth=("user", "pass"), verify=False)
    
    @task
    def power_operation(self):
        self.client.post(
            "/redfish/v1/Systems/100/Actions/ComputerSystem.Reset",
            json={"ResetType": "On"},
            auth=("user", "pass"),
            verify=False
        )
EOF

# Run load test
locust -f load_test.py --host=https://localhost:8443
```

### Profiling

```bash
# Install profiling tools
pip install cProfile

# Profile the daemon
python -m cProfile -o profile.stats src/proxmox_redfish/proxmox_redfish.py

# Analyze results
python -c "import pstats; p = pstats.Stats('profile.stats'); p.sort_stats('cumulative').print_stats(10)"
```

## Continuous Integration

### GitHub Actions

The project uses GitHub Actions for CI/CD. The workflow includes:

- **Linting**: Black, isort, flake8
- **Type Checking**: MyPy
- **Testing**: pytest with coverage
- **Security**: Bandit
- **Build**: Package building and testing

### Local CI

```bash
# Run full CI pipeline locally
./scripts/ci-local.sh

# Or run individual steps
pre-commit run --all-files
pytest tests/ --cov=src/proxmox_redfish --cov-report=xml
mypy src/
bandit -r src/
```

## Contributing Guidelines

### Before Contributing

1. **Check existing issues**: Search for similar issues or feature requests
2. **Discuss changes**: Open an issue to discuss major changes
3. **Read documentation**: Understand the current implementation
4. **Set up environment**: Follow the development setup guide

### Pull Request Guidelines

1. **Keep PRs small**: Focus on one feature or fix per PR
2. **Write tests**: Include tests for new functionality
3. **Update docs**: Update relevant documentation
4. **Follow style**: Ensure code follows project style guidelines
5. **Describe changes**: Provide clear description of changes

### Review Process

1. **Automated checks**: All CI checks must pass
2. **Code review**: At least one maintainer must approve
3. **Testing**: Changes must be tested and working
4. **Documentation**: Documentation must be updated

### Release Process

1. **Version bump**: Update version in `pyproject.toml`
2. **Changelog**: Update CHANGELOG.md
3. **Tag release**: Create git tag
4. **Build package**: Build and test package
5. **Publish**: Release to PyPI

## Additional Resources

- [Python Development Guide](https://docs.python.org/3/dev/)
- [Pytest Documentation](https://docs.pytest.org/)
- [Black Code Formatter](https://black.readthedocs.io/)
- [MyPy Type Checker](https://mypy.readthedocs.io/)
- [Pre-commit Hooks](https://pre-commit.com/)
- [Conventional Commits](https://www.conventionalcommits.org/)
- [Redfish Specification](https://www.dmtf.org/standards/redfish)
- [Proxmox VE API](https://pve.proxmox.com/pve-docs/api-viewer/)

## Getting Help

- **Issues**: Open an issue on GitHub for bugs or feature requests
- **Discussions**: Use GitHub Discussions for questions and ideas
- **Documentation**: Check the documentation in the `docs/` directory
- **Code**: Review existing code for examples and patterns

## Development Roadmap

### Short Term (Next Release)

- [ ] Add support for more Redfish endpoints
- [ ] Improve error handling and logging
- [ ] Add more comprehensive tests
- [ ] Enhance documentation

### Medium Term (Next 3 Months)

- [ ] Add support for multiple Proxmox nodes
- [ ] Implement caching for better performance
- [ ] Add metrics and monitoring
- [ ] Improve security features

### Long Term (Next 6 Months)

- [ ] Add support for Redfish events
- [ ] Implement advanced authentication methods
- [ ] Add support for Redfish tasks
- [ ] Create web-based management interface

## Contributing Checklist

Before submitting a pull request, ensure you have:

- [ ] Set up development environment
- [ ] Written tests for new functionality
- [ ] Updated documentation
- [ ] Run all tests and they pass
- [ ] Run linting and formatting tools
- [ ] Followed code style guidelines
- [ ] Added appropriate commit messages
- [ ] Created descriptive pull request
- [ ] Linked related issues

Thank you for contributing to the Proxmox Redfish Daemon project!