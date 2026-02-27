#!/bin/bash
# DNA Messenger - Dual Repository Push Script
# Pushes commits to both GitLab (primary) and GitHub (mirror)

set -e  # Exit on error

echo "=========================================="
echo "DNA Messenger - Dual Repository Push"
echo "=========================================="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if we're in a git repository
if ! git rev-parse --git-dir > /dev/null 2>&1; then
    echo -e "${RED}✗ Error: Not a git repository${NC}"
    exit 1
fi

# Get current branch
CURRENT_BRANCH=$(git rev-parse --abbrev-ref HEAD)
echo -e "${YELLOW}Current branch: $CURRENT_BRANCH${NC}"
echo ""

# Check for uncommitted changes
if ! git diff-index --quiet HEAD --; then
    echo -e "${RED}✗ Error: You have uncommitted changes${NC}"
    echo "Please commit your changes before pushing:"
    echo "  git add ."
    echo "  git commit -m \"Your message\""
    exit 1
fi

# Check if remotes are configured
if ! git remote get-url gitlab > /dev/null 2>&1; then
    echo -e "${RED}✗ Error: GitLab remote 'gitlab' not configured${NC}"
    echo "Configure with:"
    echo "  git remote add gitlab ssh://git@gitlab.cpunk.io:10000/cpunk/dna-messenger.git"
    exit 1
fi

if ! git remote get-url origin > /dev/null 2>&1; then
    echo -e "${RED}✗ Error: GitHub remote 'origin' not configured${NC}"
    echo "Configure with:"
    echo "  git remote add origin git@github.com:nocdem/dna-messenger.git"
    exit 1
fi

echo "Remotes configured:"
echo -e "  ${GREEN}gitlab${NC}: $(git remote get-url gitlab)"
echo -e "  ${GREEN}origin${NC}: $(git remote get-url origin)"
echo ""

# Push to GitLab (primary)
echo "Pushing to GitLab (primary)..."
if git push gitlab "$CURRENT_BRANCH"; then
    echo -e "${GREEN}✓ Successfully pushed to GitLab (gitlab)${NC}"
    echo ""
else
    echo -e "${RED}✗ Failed to push to GitLab${NC}"
    exit 1
fi

# Push to GitHub (mirror)
echo "Pushing to GitHub (mirror)..."
if git push origin "$CURRENT_BRANCH"; then
    echo -e "${GREEN}✓ Successfully pushed to GitHub (origin)${NC}"
    echo ""
else
    echo -e "${RED}✗ Failed to push to GitHub - MANUAL PUSH REQUIRED${NC}"
    echo "Run manually:"
    echo "  git push origin $CURRENT_BRANCH"
    exit 1
fi

# Success
echo "=========================================="
echo -e "${GREEN}✓ All remotes synchronized successfully${NC}"
echo "=========================================="
echo ""
echo "Commits pushed to:"
echo "  - GitLab: https://gitlab.cpunk.io/cpunk/dna-messenger"
echo "  - GitHub: https://github.com/nocdem/dna-messenger"
