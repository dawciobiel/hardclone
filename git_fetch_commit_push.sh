#!/usr/bin/env bash

# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Dawid Bielecki

set -euo pipefail

git fetch
git status

git add cli gui live
git commit -m "Update of submons for current commits"

git push

echo "Done."
