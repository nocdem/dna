# DNA Messenger - Git Workflow

**Last Updated:** 2025-11-21

---

## Team Workflow

DNA Messenger is developed by a **collaborative team**. Our workflow prioritizes:
- **Merge over rebase** - Preserve commit history for team visibility
- **Clear communication** - Document changes thoroughly
- **Dual-repo sync** - Always push to both GitLab and GitHub

---

## Branches

- `main` - Stable, production-ready code
- `feature/*` - New features (e.g., `feature/web-messenger`)
- `fix/*` - Bug fixes

**Integration Strategy:**
- **Prefer `git merge`** over `git rebase` to preserve team commit history
- Use merge commits to maintain context of feature development
- Only rebase local unpushed commits if needed for cleanup

---

## Commit Messages

**Format:**
```
Short summary (<50 chars)

Detailed description:
- What changed
- Why it changed
- Any breaking changes

🤖 Generated with [Claude Code](https://claude.com/claude-code)

Co-Authored-By: Claude <noreply@anthropic.com>
```

**Example:**
```
feat: Add GSK group encryption (Phase 13)

- Implement AES-256 shared keys for groups
- 200x performance improvement for large groups
- Kyber1024 key wrapping per member
- Dilithium5 owner signatures
- 57/57 unit tests passing

Breaking: Requires GSK support for group messaging

🤖 Generated with [Claude Code](https://claude.com/claude-code)

Co-Authored-By: Claude <noreply@anthropic.com>
```

---

## Pre-Commit Checklist

1. ✅ Test on Linux
2. ✅ Cross-compile for Windows
3. ✅ Remove debug `printf` statements
4. ✅ Update documentation
5. ✅ Check for memory leaks (valgrind)

---

## Push to Both Repos (MANDATORY)

DNA Messenger must be pushed to **both** GitLab and GitHub:

```bash
git add . && git commit -m "your message"
git push gitlab main    # GitLab (primary: CI/CD, builds)
git push origin main    # GitHub (mirror: public, community)
```

**Or use the script:**
```bash
./push_both.sh
```

The script:
- Checks for uncommitted changes
- Verifies remotes are configured
- Pushes to both repos
- Color-coded output

---

## Remote Setup

If remotes are not configured:

```bash
git remote add gitlab ssh://git@gitlab.cpunk.io:10000/cpunk/dna-messenger.git
git remote add origin git@github.com:nocdem/dna-messenger.git
```

Verify:
```bash
git remote -v
```

---

## Git Safety Protocol

**NEVER:**
- ❌ Update git config without permission
- ❌ Run destructive commands (`push --force`, hard reset)
- ❌ Skip hooks (`--no-verify`, `--no-gpg-sign`)
- ❌ Force push to main/master
- ❌ Amend other developers' commits

**ALWAYS:**
- ✅ Check authorship before amending: `git log -1 --format='%an %ae'`
- ✅ Use heredoc for commit messages (proper formatting)
- ✅ Only commit when user explicitly requests

---

## Creating Pull Requests

Use `gh` CLI for GitHub operations:

```bash
# Create PR
gh pr create --title "Add feature X" --body "Description"

# View PR
gh pr view 123

# Check status
gh pr status
```

**PR Body Template:**
```markdown
## Summary
- Bullet points of changes

## Test Plan
- [ ] Manual testing steps
- [ ] Unit tests passing
- [ ] Cross-platform tested

🤖 Generated with [Claude Code](https://claude.com/claude-code)
```

---

## Common Git Commands

```bash
# Status
git status

# Diff
git diff
git diff --staged

# Log
git log --oneline -10
git log --graph --oneline --all

# Branch management
git checkout -b feature/new-feature
git branch -d old-feature

# Merge (preferred for team workflow)
git checkout main
git merge feature/new-feature  # Creates merge commit

# Stash
git stash
git stash pop
git stash list

# Pull with merge (preferred)
git pull --no-rebase  # Use merge strategy
```

---

**See also:**
- [Development Guidelines](DEVELOPMENT.md) - Code style and testing
- [push_both.sh](../push_both.sh) - Automated dual-repo push script
