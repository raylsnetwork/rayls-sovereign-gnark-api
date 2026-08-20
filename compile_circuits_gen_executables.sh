#!/bin/bash

set -e  # Exit immediately if a command exits with a non-zero status


# Function to install Git LFS
install_git_lfs() {
    echo "Git LFS not found. Installing..."
    
    # Detect OS and install Git LFS
    if [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS
        if command -v brew > /dev/null 2>&1; then
            brew install git-lfs
        else
            echo "Error: Homebrew not found. Please install Homebrew first or install Git LFS manually."
            exit 1
        fi
    elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
        # Linux
        if command -v apt-get > /dev/null 2>&1; then
            # Debian/Ubuntu
            sudo apt-get update
            sudo apt-get install -y git-lfs
        elif command -v yum > /dev/null 2>&1; then
            # RHEL/CentOS/Fedora
            sudo yum install -y git-lfs
        elif command -v dnf > /dev/null 2>&1; then
            # Newer Fedora
            sudo dnf install -y git-lfs
        elif command -v pacman > /dev/null 2>&1; then
            # Arch Linux
            sudo pacman -S --noconfirm git-lfs
        else
            echo "Error: Unable to detect package manager. Please install Git LFS manually."
            exit 1
        fi
    else
        echo "Error: Unsupported operating system. Please install Git LFS manually."
        exit 1
    fi
    
    # Initialize Git LFS after installation
    git lfs install
    echo "✓ Git LFS installed successfully"
}

# Check prerequisites
[ ! -d ".git" ] && echo "Not in a Git repository" && exit 1

# Check and install Git LFS if needed
if ! command -v git-lfs > /dev/null 2>&1; then
    install_git_lfs
fi

# Pull LFS objects if needed (in case repo was cloned without LFS)
git lfs pull

BASE_DIR="."  # Adjust if needed

# ======================================
# GENERATE H PARAMETER
# ======================================

echo ""
echo "🔑 Generating H Parameter..."
echo "========================================"

# Run the H parameter generator and capture output
H_OUTPUT=$(go run cmd/setup/generate_h_parameter/main.go 2>&1)
echo "$H_OUTPUT"

# Extract Hx and Hy values from the output
NEW_HX=$(echo "$H_OUTPUT" | grep '^Hx = ' | sed 's/Hx = "\(.*\)"/\1/')
NEW_HY=$(echo "$H_OUTPUT" | grep '^Hy = ' | sed 's/Hy = "\(.*\)"/\1/')

if [ -z "$NEW_HX" ] || [ -z "$NEW_HY" ]; then
    echo ""
    echo "⚠️  Warning: Could not extract H parameter values from output"
    echo "   Skipping GroupMath.go update"
    echo ""
else
    echo ""
    echo "📝 Updating GroupMath.go with new H parameter..."
    echo "   New Hx = $NEW_HX"
    echo "   New Hy = $NEW_HY"

    # Update the Hx and Hy values in GroupMath.go
    # Use `sed -i.bak` for cross-platform compatibility (works on both BSD/macOS and GNU/Linux sed),
    # then remove the backup file.
    sed -i.bak "s/Hx = \"[0-9]*\"/Hx = \"$NEW_HX\"/" primitives/GroupMath.go
    sed -i.bak "s/Hy = \"[0-9]*\"/Hy = \"$NEW_HY\"/" primitives/GroupMath.go
    rm -f primitives/GroupMath.go.bak

    echo "✅ GroupMath.go updated successfully!"
    echo ""
fi

# ======================================
# COMPILE CIRCUITS
# ======================================

echo ""
echo "🔨 Compiling Circuits..."

go run cmd/setup/setup_r1cs.go

echo "Compilation Done..."

# ======================================
# BUILD SERVER EXECUTABLE
# ======================================

echo ""
echo "🔨 Building Go server executable..."
echo "========================================"

# Create executables directory if it doesn't exist
EXECUTABLES_DIR="last_build/executables"
echo "📁 Creating executables directory: $EXECUTABLES_DIR"
if [ ! -d "$EXECUTABLES_DIR" ]; then
    mkdir -p "$EXECUTABLES_DIR"
    echo "✓ Directory created: $EXECUTABLES_DIR"
else
    echo "✓ Directory already exists: $EXECUTABLES_DIR"
fi

# Build the server
SERVER_PATH="$EXECUTABLES_DIR/server"
echo ""
echo "🏗️  Compiling Go server..."
echo "   Source: ./cmd/server/main.go"
echo "   Target: $SERVER_PATH"
echo "   Build flags: CGO_ENABLED=1, ldflags='-s -w'"

# Capture build start time
BUILD_START=$(date +%s)

# Run the build command and capture both stdout and stderr
if CGO_ENABLED=1 go build -ldflags="-s -w" -o "$SERVER_PATH" ./cmd/server/main.go 2>&1; then
    BUILD_END=$(date +%s)
    BUILD_TIME=$((BUILD_END - BUILD_START))
    
    # Check if the binary was actually created
    if [ -f "$SERVER_PATH" ]; then
        # Get file info
        SERVER_SIZE=$(du -h "$SERVER_PATH" | cut -f1)
        SERVER_PERMISSIONS=$(ls -l "$SERVER_PATH" | cut -d' ' -f1)
        
        echo ""
        echo "✅ SERVER BUILD SUCCESSFUL!"
        echo "========================================"
        echo "📍 Server binary location: $SERVER_PATH"
        echo "📏 Binary size: $SERVER_SIZE"
        echo "🔐 Permissions: $SERVER_PERMISSIONS"
        echo "⏱️  Build time: ${BUILD_TIME}s"
        echo ""
        echo "🚀 Server is ready to run!"
        echo "   To start: ./run_gnark_server.sh"
        echo "   Or use: ./run_docker.sh (to run in Docker)"
        echo ""
    else
        echo ""
        echo "❌ BUILD ERROR: Binary not found at expected location!"
        echo "Expected: $SERVER_PATH"
        exit 1
    fi
else
    echo ""
    echo "❌ SERVER BUILD FAILED!"
    echo "========================================"
    echo "Build command failed. Check the error messages above."
    echo "Common issues:"
    echo "  - Missing dependencies (run 'go mod tidy')"
    echo "  - CGO compilation errors"
    echo "  - Source file not found: ./cmd/server/main.go"
    echo ""
    exit 1
fi

echo "🎉 SETUP COMPLETE!"
echo "========================================"
echo "✅ Verifier contracts converted"
echo "✅ Server binary built and ready"
echo "✅ All executables in: $EXECUTABLES_DIR"
echo ""