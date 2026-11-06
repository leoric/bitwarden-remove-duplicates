# Bitwarden Duplicate Removal

Remove duplicate logins from your Bitwarden vault using only the official Bitwarden CLI (`bw`). Nothing is exported to a file, nothing is sent to a third party, and secrets are never printed, logged, or placed on a command line. You can verify this by reading the script.

The script is conservative by design: it merges what is worth keeping, moves redundant items to the Trash (never a permanent delete), and records everything it does so it can be undone.

## Requirements

- Python 3.8+ (standard library only)
- The official Bitwarden CLI

### Install the Bitwarden CLI

**macOS**

```
brew install bitwarden-cli
```

or via npm:

```
npm install -g @bitwarden/cli
```

**Ubuntu**

```
snap install bw
```

**Other Linux distros**

Download the latest `bw-linux-*.zip` from the [official releases](https://github.com/bitwarden/clients/releases), then:

```
unzip bw-linux-*.zip
sudo mv bw /usr/local/bin/
sudo chmod +x /usr/local/bin/bw
```

## Login

```
bw login
export BW_SESSION="$(bw unlock --raw)"
```

The script runs `bw sync` itself (skip with `--no-sync`).

## Usage

Always start with a dry run. It prints the full report and changes nothing:

```
./bitwarden-remove-duplicates.py --dry-run
```

When the report looks right, run it for real:

```
./bitwarden-remove-duplicates.py
```

You must type `DELETE <n>` (with the exact number of items listed) to proceed.

### Example report

```
=== 1 duplicate group(s) to clean up ===

  Group 1
    KEEP    c2  "Shop"
            folder: Work | org: (personal) | modified: 2023-01-01
            username: leila@example.com | password: ******** (6 chars, identical)
            URLs: http://shop.com
            has: notes, custom fields, TOTP
    TRASH   c1  "Shop"
            folder: Work | org: (personal) | modified: 2024-05-01
            username: Leila@example.com | password: ******** (6 chars, identical)
            URLs: https://www.shop.com/
            merge into KEEP: add URL https://www.shop.com/

=== 1 group(s) SKIPPED (will not be touched) ===
  Reason: more than one item has attachments/passkeys, which the CLI cannot merge. Review manually.
  ...

Total: 1 item(s) would be moved to Trash, 1 kept item(s) would be updated.
```

### Options

| Option | Description |
| --- | --- |
| `--dry-run` | Print the report and exit. No changes are made. |
| `--url-match full\|host` | `full` (default) compares host + path. `host` compares hostnames only (more aggressive). |
| `--ignore-folder` | Allow items in different folders to match. Never crosses organizations. |
| `--no-sync` | Skip `bw sync` at startup. |
| `--log PATH` | Action log path. Default: `./bw-dedupe-<timestamp>.jsonl`. |
| `--restore LOG` | Restore items trashed in a previous run (see below). |

## What counts as a duplicate

Two login items are duplicates only if **all** of the following match:

- Organization
- Folder (unless `--ignore-folder`)
- Collections
- Username (case-insensitive)
- Password (exact match)
- The set of normalized URLs

URL normalization ignores the scheme, a leading `www.`, default ports, trailing slashes, query strings, and fragments. If an item has no URL, its name must also match.

Because of this, the same username and password on two different websites, in two different organizations, or in two different folders are **never** treated as duplicates.

## What gets merged

Before a duplicate is trashed, the following are merged into the item that is kept, so nothing is lost:

- All distinct URLs. Variants that differ only by `www.`, host case or a trailing slash are not duplicated. An `https` URL may be added to a kept `http` item, but an `http` URL is never added when the `https` version is already present
- Notes (appended if not already present)
- Custom fields
- TOTP (adopted if the kept item has none; if both have different secrets, the second is saved as a hidden custom field)
- Favorite flag and master-password re-prompt setting
- Password history (latest 5 entries)

The item kept is the one with the most content. If items are otherwise equal, the one with `https` URLs is preferred, and the newest revision is only the final tie-breaker.

### Not mergeable: attachments and passkeys

The CLI cannot move attachments or passkeys between items. An item that has them is always the one kept. If two items in a group both have them, the whole group is skipped and listed in the report for manual review.

## Safety and recovery

- **Report first.** Every group shows the kept item, the items to be trashed (ID, name, folder, organization, URLs, modified date), and exactly what will be merged. Passwords are masked.
- **Trash, not permanent delete.** Items are removed with `bw delete item` (no `--permanent`), so they stay in the Trash and can be recovered there.
- **Merge before delete.** If merging into the kept item fails, its duplicates are not deleted.
- **Stale-data check.** If the kept item changed since it was listed, that group is aborted.
- **Action log.** Every merge and deletion is recorded (ID, name, URLs, timestamp, status) in a JSONL log created with `0600` permissions. It contains no passwords or other secrets.

### Undo

```
./bitwarden-remove-duplicates.py --restore bw-dedupe-20250101-120000.jsonl
```

This lists the items trashed in that run and restores them after you type `RESTORE`. Restoring is additive: information that was merged into a kept item is not removed from it. Note that Bitwarden permanently purges Trash items after 30 days.

## Limitations

- Only login items are considered (not cards, identities, or secure notes).
- Items with an empty password are ignored.
- Matching is intentionally strict. For example, `shop.com` and `shop.com/login` are treated as different sites unless you use `--url-match host`.
- Attachments and passkeys are never merged (see above).