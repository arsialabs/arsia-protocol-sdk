#!/bin/sh
set -e

# Install the ARSIA Protocol SDK from the volume-mounted path if present
# and not already installed.
if [ -d "/sdk" ] && ! python -c "import arsia_protocol" 2>/dev/null; then
    pip install --no-cache-dir /sdk
fi

exec "$@"
