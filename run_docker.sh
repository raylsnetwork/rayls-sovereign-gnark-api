#!/bin/bash

set -e  # Exit immediately if a command exits with a non-zero status

docker build --tag 'gnark' --debug .
docker run --rm -it --expose 3003 -p 3003:3003 gnark