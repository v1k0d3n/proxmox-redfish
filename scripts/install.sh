#!/bin/bash

# Proxmox Redfish Daemon Installation Script
# This script automates the installation from GitHub directly and setups the Proxmox Redfish daemon with basic SSL support

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default values
INSTALL_DIR="/opt/proxmox-redfish"
GITLAB_URL="https://github.com/v1k0d3n/proxmox-redfish.git"
SERVICE_USER="proxmox-redfish"

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root"
        print_status "Please run as root user (Proxmox VE standard)"
        exit 1
    fi
}

# Function to check dependencies
check_dependencies() {
    print_status "Checking dependencies..."
    
    # Check if Python 3 is installed
    if ! command -v python3 &> /dev/null; then
        print_error "Python 3 is not installed"
        print_status "Please install Python 3.8 or higher"
        exit 1
    fi
    
    # Check Python version
    PYTHON_VERSION=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
    if [[ $(echo "$PYTHON_VERSION >= 3.8" | bc -l) -eq 0 ]]; then
        print_error "Python 3.8 or higher is required (found $PYTHON_VERSION)"
        exit 1
    fi
    
    # Check if pip is installed
    if ! command -v pip3 &> /dev/null; then
        print_error "pip3 is not installed"
        print_status "Please install pip3"
        exit 1
    fi
    
    # Check if openssl is installed
    if ! command -v openssl &> /dev/null; then
        print_error "OpenSSL is not installed"
        print_status "Please install OpenSSL"
        exit 1
    fi
    
    print_success "All dependencies are satisfied"
}

# Function to create installation directory
create_install_dir() {
    print_status "Creating installation directory..."
    
    if [[ -d "$INSTALL_DIR" ]]; then
        print_warning "Installation directory already exists: $INSTALL_DIR"
        read -p "Do you want to continue? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            print_status "Installation cancelled"
            exit 0
        fi
    fi
    
    mkdir -p "$INSTALL_DIR"
    cd "$INSTALL_DIR"
    
    print_success "Installation directory created: $INSTALL_DIR"
}

# Function to create virtual environment
create_venv() {
    print_status "Creating virtual environment..."
    
    python3 -m venv venv
    source venv/bin/activate
    
    # Upgrade pip
    pip install --upgrade pip
    
    print_success "Virtual environment created"
}

# Function to install from GitLab
install_from_gitlab() {
    print_status "Installing from GitLab repository..."
    
    pip install git+"$GITLAB_URL"
    
    print_success "Package installed successfully"
}

# Function to generate SSL certificate
generate_ssl_cert() {
    print_status "Generating SSL certificate..."
    
    if [[ -f "cert.pem" ]] || [[ -f "key.pem" ]]; then
        print_warning "SSL certificate files already exist"
        read -p "Do you want to regenerate them? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            print_status "Using existing SSL certificates"
            return
        fi
    fi
    
    # Generate self-signed certificate
    openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/CN=localhost"
    chmod 600 key.pem cert.pem
    
    print_success "SSL certificate generated"
}

# Function to setup systemd service
setup_systemd_service() {
    print_status "Setting up systemd service..."
    
    # Find the service file in the installed package
    SERVICE_FILE_PATH=$(find venv/lib/python*/site-packages/proxmox_redfish/config/ -name "proxmox-redfish.service" 2>/dev/null | head -1)
    
    if [[ -z "$SERVICE_FILE_PATH" ]]; then
        print_error "Service file not found in installed package"
        print_status "Please check the installation"
        exit 1
    fi
    
    # Copy service file
    cp "$SERVICE_FILE_PATH" /etc/systemd/system/
    
    # Update service file to use the correct paths
    sed -i "s|ExecStart=.*|ExecStart=$INSTALL_DIR/venv/bin/proxmox-redfish|g" /etc/systemd/system/proxmox-redfish.service
    sed -i "s|WorkingDirectory=.*|WorkingDirectory=$INSTALL_DIR|g" /etc/systemd/system/proxmox-redfish.service
    sed -i "s|User=.*|User=root|g" /etc/systemd/system/proxmox-redfish.service
    sed -i "s|Group=.*|Group=root|g" /etc/systemd/system/proxmox-redfish.service
    
    # Reload systemd
    systemctl daemon-reload
    
    print_success "Systemd service configured"
}

# Function to create configuration template
create_config_template() {
    print_status "Creating configuration template..."
    
    cat > config/config.json.template << EOF
{
    "proxmox": {
        "host": "your-proxmox-host",
        "user": "your-proxmox-user",
        "password": "your-proxmox-password"
    },
    "redfish": {
        "port": 8443,
        "ssl_cert": "$INSTALL_DIR/cert.pem",
        "ssl_key": "$INSTALL_DIR/key.pem"
    },
    "logging": {
        "level": "INFO"
    }
}
EOF
    
    print_success "Configuration template created: config/config.json.template"
}

# Function to create environment file template
create_env_template() {
    print_status "Creating environment file template..."
    
    cat > .env.template << EOF
# Proxmox Configuration
PROXMOX_HOST=your-proxmox-host
PROXMOX_USER=your-proxmox-user
PROXMOX_PASSWORD=your-proxmox-password

# Redfish Configuration
REDFISH_PORT=8443
SSL_CERT_FILE=$INSTALL_DIR/cert.pem
SSL_KEY_FILE=$INSTALL_DIR/key.pem

# Logging
LOG_LEVEL=INFO
EOF
    
    print_success "Environment file template created: .env.template"
}

# Function to display next steps
display_next_steps() {
    echo
    print_success "Installation completed successfully!"
    echo
    print_status "Next steps:"
    echo "1. Configure your Proxmox credentials:"
    echo "   - Copy .env.template to .env"
    echo "   - Edit .env with your Proxmox details"
    echo
    echo "2. Or use configuration file:"
    echo "   - Copy config/config.json.template to config/config.json"
    echo "   - Edit config/config.json with your settings"
    echo
    echo "3. Start the service:"
    echo "   sudo systemctl start proxmox-redfish"
    echo "   sudo systemctl enable proxmox-redfish"
    echo
    echo "4. Check service status:"
    echo "   sudo systemctl status proxmox-redfish"
    echo
    echo "5. View logs:"
    echo "   sudo journalctl -u proxmox-redfish -f"
    echo
    print_status "The daemon will be available at: https://localhost:8443/redfish/v1"
}

# Main installation function
main() {
    echo "=========================================="
    echo "Proxmox Redfish Daemon Installation Script"
    echo "=========================================="
    echo
    
    check_root
    check_dependencies
    create_install_dir
    create_venv
    install_from_gitlab
    generate_ssl_cert
    setup_systemd_service
    create_config_template
    create_env_template
    display_next_steps
}

# Run main function
main "$@" 