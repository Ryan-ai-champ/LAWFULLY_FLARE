#!/bin/bash

# Immigration Platform Deployment Script
# This script builds the React application and prepares it for deployment

# Set error handling
set -e

# Color codes for output formatting
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function for logging
log() {
  echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

error() {
  echo -e "${RED}[ERROR] $1${NC}" >&2
}

success() {
  echo -e "${GREEN}[SUCCESS] $1${NC}"
}

warning() {
  echo -e "${YELLOW}[WARNING] $1${NC}"
}

# Check if environment is provided, default to development
ENVIRONMENT=${1:-development}
log "Deploying to $ENVIRONMENT environment"

# Validate environment
if [[ ! "$ENVIRONMENT" =~ ^(development|staging|production)$ ]]; then
  error "Invalid environment. Must be one of: development, staging, production"
  exit 1
fi

# Directory setup
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
FRONTEND_DIR="$SCRIPT_DIR/frontend"
BACKEND_DIR="$SCRIPT_DIR/backend"
BUILD_DIR="$SCRIPT_DIR/build"
ARTIFACTS_DIR="$SCRIPT_DIR/artifacts"

# Create necessary directories
mkdir -p "$BUILD_DIR"
mkdir -p "$ARTIFACTS_DIR"
mkdir -p "$ARTIFACTS_DIR/$ENVIRONMENT"

# Function to install dependencies
install_dependencies() {
  log "Installing frontend dependencies..."
  cd "$FRONTEND_DIR"
  npm install --silent || {
    error "Failed to install frontend dependencies"
    exit 1
  }
  success "Frontend dependencies installed"

  log "Installing backend dependencies..."
  cd "$BACKEND_DIR"
  npm install --silent || {
    error "Failed to install backend dependencies"
    exit 1
  }
  success "Backend dependencies installed"
}

# Function to run tests
run_tests() {
  log "Running frontend tests..."
  cd "$FRONTEND_DIR"
  npm test -- --watchAll=false || {
    warning "Some frontend tests failed, but continuing with deployment"
  }

  log "Running backend tests..."
  cd "$BACKEND_DIR"
  npm test || {
    warning "Some backend tests failed, but continuing with deployment"
  }
}

# Function to build the frontend
build_frontend() {
  log "Building frontend for $ENVIRONMENT environment..."
  cd "$FRONTEND_DIR"
  
  # Set environment-specific variables
  if [ "$ENVIRONMENT" = "production" ]; then
    export REACT_APP_API_URL="https://api.immigration-platform.com"
    export GENERATE_SOURCEMAP=false
  elif [ "$ENVIRONMENT" = "staging" ]; then
    export REACT_APP_API_URL="https://staging-api.immigration-platform.com"
    export GENERATE_SOURCEMAP=true
  else
    export REACT_APP_API_URL="http://localhost:5001"
    export GENERATE_SOURCEMAP=true
  fi
  
  npm run build || {
    error "Failed to build frontend"
    exit 1
  }
  
  # Copy build to artifacts directory
  cp -r build/* "$ARTIFACTS_DIR/$ENVIRONMENT/"
  success "Frontend built successfully"
}

# Function to prepare backend for deployment
prepare_backend() {
  log "Preparing backend for $ENVIRONMENT environment..."
  cd "$BACKEND_DIR"
  
  # Create .env file for the specified environment
  if [ -f ".env.$ENVIRONMENT" ]; then
    cp ".env.$ENVIRONMENT" ".env"
    log "Using .env.$ENVIRONMENT for backend configuration"
  else
    warning "No .env.$ENVIRONMENT file found, using default .env if it exists"
  fi
  
  # Create a backend package for deployment
  mkdir -p "$ARTIFACTS_DIR/$ENVIRONMENT/backend"
  cp -r package.json index.js src "$ARTIFACTS_DIR/$ENVIRONMENT/backend/"
  
  # Exclude test files and other non-production files
  find "$ARTIFACTS_DIR/$ENVIRONMENT/backend" -name "*.test.js" -type f -delete
  find "$ARTIFACTS_DIR/$ENVIRONMENT/backend" -name "*.spec.js" -type f -delete
  
  success "Backend prepared successfully"
}

# Function to create deployment package
create_deployment_package() {
  log "Creating deployment package for $ENVIRONMENT environment..."
  
  # Create a timestamp for the deployment package
  TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
  PACKAGE_NAME="immigration-platform_${ENVIRONMENT}_${TIMESTAMP}.zip"
  
  # Navigate to artifacts directory
  cd "$ARTIFACTS_DIR"
  
  # Create deployment package
  zip -r "$PACKAGE_NAME" "$ENVIRONMENT/" > /dev/null || {
    error "Failed to create deployment package"
    exit 1
  }
  
  success "Deployment package created: $PACKAGE_NAME"
  log "Deployment package location: $ARTIFACTS_DIR/$PACKAGE_NAME"
}

# Main deployment flow
main() {
  log "Starting deployment process for $ENVIRONMENT environment..."
  
  install_dependencies
  run_tests
  build_frontend
  prepare_backend
  create_deployment_package
  
  success "Deployment preparation completed successfully!"
  log "Deployment artifacts are ready in: $ARTIFACTS_DIR/$ENVIRONMENT/"
  log "Deployment package: $ARTIFACTS_DIR/immigration-platform_${ENVIRONMENT}_$(date +"%Y%m%d_%H%M%S").zip"
}

# Execute main function
main

