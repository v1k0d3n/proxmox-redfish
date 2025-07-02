#!/bin/bash

# Development setup script for proxmox-redfish
set -e

echo "🚀 Setting up proxmox-redfish development environment..."

# Check if Python 3.8+ is available
python_version=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
required_version="3.8"

if [ "$(printf '%s\n' "$required_version" "$python_version" | sort -V | head -n1)" != "$required_version" ]; then
    echo "❌ Python 3.8+ is required. Found: $python_version"
    exit 1
fi

echo "✅ Python version: $python_version"

# Create virtual environment if it doesn't exist
if [ ! -d "venv" ]; then
    echo "📦 Creating virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment
echo "🔧 Activating virtual environment..."
source venv/bin/activate

# Upgrade pip
echo "⬆️  Upgrading pip..."
pip install --upgrade pip

# Install dependencies
echo "📚 Installing dependencies..."
pip install -r requirements.txt
pip install -r requirements-dev.txt

# Install pre-commit hooks
echo "🔗 Installing pre-commit hooks..."
pre-commit install

# Run initial tests
echo "🧪 Running initial tests..."
pytest tests/unit/ -v

echo "✅ Development environment setup complete!"
echo ""
echo "📋 Available commands:"
echo "  pytest tests/unit/ -v          # Run unit tests"
echo "  pytest tests/integration/ -v   # Run integration tests"
echo "  black src/ tests/              # Format code"
echo "  isort src/ tests/              # Sort imports"
echo "  flake8 src/ tests/             # Lint code"
echo "  mypy src/                      # Type checking"
echo "  bandit -r src/                 # Security scan"
echo "  pre-commit run --all-files     # Run all pre-commit hooks"
echo ""
echo "🎯 Happy coding!" 