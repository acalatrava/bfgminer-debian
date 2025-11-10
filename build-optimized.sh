#!/bin/bash
#
# Build script for optimized BFGMiner with modern CPU support
#

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}================================${NC}"
echo -e "${GREEN}BFGMiner Optimized Build Script${NC}"
echo -e "${GREEN}================================${NC}"
echo ""

# Detect architecture
ARCH=$(uname -m)
echo -e "${YELLOW}Detected architecture: ${ARCH}${NC}"

# Set optimization flags based on architecture
OPTFLAGS="-O3"

case "$ARCH" in
    x86_64|amd64)
        echo "Configuring for x86_64 with SHA-NI support..."
        OPTFLAGS="$OPTFLAGS -march=native"
        # Check if CPU supports SHA-NI
        if grep -q 'sha_ni' /proc/cpuinfo 2>/dev/null; then
            echo -e "${GREEN}✓ SHA-NI support detected${NC}"
            OPTFLAGS="$OPTFLAGS -msha -msse4.1"
        else
            echo -e "${YELLOW}⚠ SHA-NI not detected, using standard optimizations${NC}"
        fi
        ;;
    i386|i686)
        echo "Configuring for x86_32 with SHA-NI support..."
        OPTFLAGS="$OPTFLAGS -march=native"
        if grep -q 'sha_ni' /proc/cpuinfo 2>/dev/null; then
            echo -e "${GREEN}✓ SHA-NI support detected${NC}"
            OPTFLAGS="$OPTFLAGS -msha -msse4.1"
        else
            echo -e "${YELLOW}⚠ SHA-NI not detected, using standard optimizations${NC}"
        fi
        ;;
    aarch64|arm64)
        echo "Configuring for ARM64 with Crypto Extensions..."
        # Check for crypto extensions
        if grep -q 'sha2' /proc/cpuinfo 2>/dev/null || grep -q 'sha256' /proc/cpuinfo 2>/dev/null; then
            echo -e "${GREEN}✓ ARM Crypto Extensions detected${NC}"
            OPTFLAGS="$OPTFLAGS -march=armv8-a+crypto"
        else
            echo -e "${YELLOW}⚠ ARM Crypto Extensions not detected, using standard optimizations${NC}"
            OPTFLAGS="$OPTFLAGS -march=armv8-a"
        fi
        ;;
    *)
        echo -e "${YELLOW}⚠ Unknown architecture, using generic optimizations${NC}"
        OPTFLAGS="-O2"
        ;;
esac

echo ""
echo "Optimization flags: $OPTFLAGS"
echo ""

# Check for required dependencies
echo "Checking dependencies..."
MISSING_DEPS=0

check_command() {
    if ! command -v $1 &> /dev/null; then
        echo -e "${RED}✗ $1 not found${NC}"
        MISSING_DEPS=1
    else
        echo -e "${GREEN}✓ $1 found${NC}"
    fi
}

check_command gcc
check_command make
check_command automake
check_command pkg-config

if [ $MISSING_DEPS -eq 1 ]; then
    echo ""
    echo -e "${RED}Missing dependencies. Please install them first:${NC}"
    echo ""
    echo "Ubuntu/Debian:"
    echo "  sudo apt-get install build-essential automake libtool pkg-config"
    echo "  sudo apt-get install libcurl4-openssl-dev libjansson-dev libncurses5-dev"
    echo ""
    exit 1
fi

echo ""
echo "All dependencies found!"
echo ""

# Generate configure script if needed
if [ ! -f configure ]; then
    echo "Generating configure script..."
    ./autogen.sh
    echo ""
fi

# Configure
echo "Configuring BFGMiner..."
./configure \
    --enable-cpumining \
    --disable-opencl \
    --disable-scrypt \
    CFLAGS="$OPTFLAGS" \
    "$@"

echo ""
echo "Building BFGMiner..."
make clean 2>/dev/null || true
make -j$(nproc)

echo ""
echo -e "${GREEN}================================${NC}"
echo -e "${GREEN}Build completed successfully!${NC}"
echo -e "${GREEN}================================${NC}"
echo ""
echo "Binary location: ./bfgminer"
echo ""
echo "To install system-wide:"
echo "  sudo make install"
echo ""
echo "To test the optimized version:"
echo "  ./bfgminer --algo auto --benchmark"
echo ""
echo "For more information, see README.CPU.OPTIMIZATIONS.md"

