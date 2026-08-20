#!/bin/bash
set -e

cleanup() {
    echo "Shutting down server..."
    jobs -p | xargs -r kill
    exit 0
}

trap cleanup SIGINT SIGTERM EXIT

echo "Starting server..."
GOMAXPROCS=$(nproc) ./last_build/executables/server