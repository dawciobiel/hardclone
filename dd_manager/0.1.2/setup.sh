#!/usr/bin/env bash

set -e  # Exit immediately if a command exits with a non-zero status

echo "🔧 Checking Python virtual environment (.venv)..."

# Create the virtual environment if it doesn't exist
if [ ! -d ".venv" ]; then
  echo "📦 Creating a new virtual environment (.venv)..."
  python3 -m venv .venv
else
  echo "✅ Virtual environment already exists – skipping creation."
fi

# Check if pip exists in the virtual environment
if [ ! -x ".venv/bin/pip" ]; then
  echo "❌ Error: 'pip' not found in the virtual environment."
  exit 1
fi

# Activate the environment (only within this script)
echo "🧪 Activating the virtual environment..."
source .venv/bin/activate

# Install dependencies
echo "📥 Installing dependencies from requirements.txt..."
pip install -r requirements.txt

# Deactivate the environment (optional, as the script ends here anyway)
echo "🔌 Deactivating the virtual environment..."
deactivate

echo "✅ Environment setup complete!"
