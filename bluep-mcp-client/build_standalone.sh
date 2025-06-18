#!/bin/bash
# Build standalone distribution of bluep-mcp-client

set -e

echo "Building bluep-mcp-client standalone distribution..."

# Clean previous builds
rm -rf dist/ build/ *.egg-info

# Create wheel
python -m pip install --upgrade build
python -m build

echo "Build complete! Distribution files in ./dist/"
echo ""
echo "To install on another machine:"
echo "  pip install dist/bluep_mcp_client-*.whl"
echo ""
echo "Or upload to PyPI:"
echo "  pip install twine"
echo "  twine upload dist/*"