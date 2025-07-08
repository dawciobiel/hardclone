#!/usr/bin/env bash

set -e

if [ ! -d ".venv" ]; then
  python3 -m venv .venv
fi

# Bash shell
# source ./.venv/bin/activate

# # Fish shell
source ./.venv/bin/activate.fish

pip install -r requirements.txt

# Bash shell
# source ./.venv/bin/deactivate

# # Fish shell
source ./.venv/bin/deactivate.fish

