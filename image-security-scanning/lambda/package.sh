#!/bin/bash

# Package Lambda function for deployment
set -e

echo "Packaging Lambda function..."

# Create temporary directory
TEMP_DIR=$(mktemp -d)
echo "Using temporary directory: $TEMP_DIR"

# Copy Python file
cp process_scan_results.py "$TEMP_DIR/index.py"

# Create deployment package
cd "$TEMP_DIR"
zip -r ../process_scan_results.zip .

# Move to terraform directory
mv ../process_scan_results.zip ../terraform/process_scan_results.zip

echo "Lambda package created: terraform/process_scan_results.zip"

# Cleanup
rm -rf "$TEMP_DIR"

echo "Packaging complete!"