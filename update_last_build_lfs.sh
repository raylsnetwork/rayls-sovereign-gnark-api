#!/bin/bash

# Automated version - no prompts
set -e

# Function to install Git LFS
install_git_lfs() {
    echo "Git LFS not found. Installing..."
    
    # Detect OS and install Git LFS
    if [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS
        if command -v brew > /dev/null 2>&1; then
            brew install git-lfs
        else
            echo "Error: Homebrew not found. Please install Homebrew first or install Git LFS manually."
            exit 1
        fi
    elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
        # Linux
        if command -v apt-get > /dev/null 2>&1; then
            # Debian/Ubuntu
            sudo apt-get update
            sudo apt-get install -y git-lfs
        elif command -v yum > /dev/null 2>&1; then
            # RHEL/CentOS/Fedora
            sudo yum install -y git-lfs
        elif command -v dnf > /dev/null 2>&1; then
            # Newer Fedora
            sudo dnf install -y git-lfs
        elif command -v pacman > /dev/null 2>&1; then
            # Arch Linux
            sudo pacman -S --noconfirm git-lfs
        else
            echo "Error: Unable to detect package manager. Please install Git LFS manually."
            exit 1
        fi
    else
        echo "Error: Unsupported operating system. Please install Git LFS manually."
        exit 1
    fi
    
    # Initialize Git LFS after installation
    git lfs install
    echo "✓ Git LFS installed successfully"
}

# Check prerequisites
[[ ! -d ".git" ]] && echo "Not in a Git repository" >&2 && exit 1
[[ ! -d "last_build" ]] && echo "last_build not found" >&2 && exit 1

# Check and install Git LFS if needed
if ! command -v git-lfs > /dev/null 2>&1; then
    install_git_lfs
fi

# Pass --push to also push the commit and its LFS objects.
PUSH=false
[[ "${1:-}" = "--push" ]] && PUSH=true

# Stage and commit only last_build/: a pathspec commit leaves any other
# staged changes out of the artifacts commit.
git add last_build/
if ! git diff --staged --quiet -- last_build/; then
    BRANCH=$(git branch --show-current)
    git commit -m "chore(build): regenerate circuit artifacts ($(date '+%Y-%m-%d'))" -- last_build/
    if $PUSH; then
        git lfs push origin "$BRANCH"
        git push origin "$BRANCH"
        echo "✓ Build artifacts committed and pushed"
    else
        echo "✓ Build artifacts committed locally; rerun with --push or push manually"
    fi
else
    echo "No changes to commit"
fi

# Cleanup
git lfs prune --verify-remote