# Database Migrations

## Running Migrations

Migrations should be run as the database superuser (postgres) or a user with sufficient privileges.

### Manual Migration

```bash
# Run a migration file
PGPASSWORD=your_password psql -h ai.cpunk.io -U postgres -d dna_messenger -f migrations/001_add_groups.sql
```

### Migration 002: Fix NULL delivered_at (Optional)

**File:** `002_fix_delivered_at.sql`

**Description:** Fixes messages that were marked as read before the COALESCE fix was implemented. Sets `delivered_at = read_at` for all read messages where `delivered_at` is NULL.

**Note:** This migration is optional and only affects historical data. New messages will have `delivered_at` set correctly automatically.

**Warning:** On large databases, this migration may take a long time or timeout. It can be run in batches:

```sql
-- Run in batches of 1000 messages
UPDATE messages
SET delivered_at = read_at
WHERE id IN (
    SELECT id FROM messages
    WHERE status = 'read'
      AND delivered_at IS NULL
      AND read_at IS NOT NULL
    LIMIT 1000
);
-- Repeat until no more rows are affected
```

## Migration History

| Migration | Date | Description | Status |
|-----------|------|-------------|--------|
| 001_add_groups.sql | 2025-10-15 | Add groups and group_members tables | ✅ Applied |
| 002_fix_delivered_at.sql | 2025-10-15 | Fix NULL delivered_at for read messages | ⚠️ Optional |
