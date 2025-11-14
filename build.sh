#!/bin/bash

set -e

echo "Building signcheck for multiple platforms..."

# Build for Windows
GOOS=windows GOARCH=amd64 go build -o signcheck-windows-amd64.exe signcheck.go
GOOS=windows GOARCH=arm64 go build -o signcheck-windows-arm64.exe signcheck.go
echo "✓ Windows builds complete"

# Build for macOS
GOOS=darwin GOARCH=amd64 go build -o signcheck-macos-amd64 signcheck.go
GOOS=darwin GOARCH=arm64 go build -o signcheck-macos-arm64 signcheck.go
echo "✓ macOS builds complete"

# Build for Linux
GOOS=linux GOARCH=amd64 go build -o signcheck-linux-amd64 signcheck.go
GOOS=linux GOARCH=arm64 go build -o signcheck-linux-arm64 signcheck.go
echo "✓ Linux builds complete"

echo ""
echo "All builds completed successfully!"
echo ""
echo "Generated binaries:"
ls -lh signcheck-* 2>/dev/null | awk '{print "  " $9 " (" $5 ")"}'
