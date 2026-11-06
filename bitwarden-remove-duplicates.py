#!/usr/bin/env python3
"""
bitwarden-remove-duplicates (safe rewrite)

Finds duplicate *login* items in a Bitwarden vault using only the official `bw` CLI,
merges anything worth keeping into the surviving entry, and moves the redundant
entries to the Trash (never a permanent delete).

Safety properties
  * Two items are duplicates only if ALL of these match:
      organization, folder, collections, username (case-insensitive),
      password (exact), and the set of normalized URLs.
    Items with no URL must also share the same name.
  * Different websites / organizations / folders are never merged.
  * URLs, notes, custom fields, TOTP, favorite flag and password history from the
    removed items are merged into the kept item before anything is deleted (names are not recorded).
  * Items with attachments or passkeys cannot be merged through the CLI. They are
    always kept; if two items in a group have them, the group is skipped.
  * A full report is printed first. --dry-run stops there.
  * Deletion = move to Trash (`bw delete item`, no --permanent). Every action is
    written to a JSONL log (IDs and names only, no secrets), and
    `--restore LOG` brings the deleted items back out of the Trash.
  * Secrets are never printed, never written to disk, and never put on a command
    line (merged items are passed to `bw edit` via stdin).

Usage
  export BW_SESSION="$(bw unlock --raw)"
  ./bitwarden-remove-duplicates.py --dry-run
  ./bitwarden-remove-duplicates.py
  ./bitwarden-remove-duplicates.py --restore bw-dedupe-20250101-120000.jsonl
"""
import argparse
import base64
import copy
import json
import os
import subprocess
import sys
from collections import defaultdict
from datetime import datetime, timezone
from urllib.parse import urlsplit

TYPE_LOGIN = 1
FIELD_HIDDEN = 1


class BwError(RuntimeError):
    pass


def bw(*args, stdin=None):
    try:
        r = subprocess.run(["bw", *args, "--nointeraction"], input=stdin,
                           capture_output=True, text=True)
    except FileNotFoundError:
        sys.exit("error: `bw` CLI not found in PATH")
    if r.returncode != 0:
        raise BwError((r.stderr or r.stdout).strip() or f"bw {args[0]} failed")
    return r.stdout


def clean(s):
    """Make vault-controlled text safe to print (no control/escape characters)."""
    return "".join(c if c.isprintable() else "?" for c in str(s or ""))


# ----------------------------------------------------------------------------- URLs
def normalize_url(raw, mode="full"):
    """Scheme-less, www-less, lowercase host; default ports dropped; no query/fragment.
    mode='host' compares the host only."""
    u = (raw or "").strip()
    if not u:
        return None
    if u.lower().startswith(("androidapp://", "iosapp://")):
        return u.lower()
    if "://" not in u:
        u = "https://" + u
    try:
        p = urlsplit(u)
        host = (p.hostname or "").lower()
        port = p.port
    except ValueError:
        return u.lower()
    if not host:
        return u.lower()
    if host.startswith("www."):
        host = host[4:]
    if mode == "host":
        return host
    default = {"http": 80, "https": 443}.get(p.scheme.lower())
    netloc = host + (f":{port}" if port and port != default else "")
    return netloc + p.path.rstrip("/")


def url_identity(raw):
    """Light comparison used when merging: ignores a leading www., the case of scheme/host
    and a trailing slash. The scheme is kept: http vs https is handled in merge()."""
    u = (raw or "").strip()
    try:
        p = urlsplit(u)
        if not p.scheme or not p.netloc:
            return u.lower() if "://" not in u else u
        netloc = p.netloc.lower()
        if netloc.startswith("www."):
            netloc = netloc[4:]
        return p._replace(scheme=p.scheme.lower(), netloc=netloc,
                          path=p.path.rstrip("/")).geturl()
    except ValueError:
        return u


def urls_of(item):
    return [u.get("uri") for u in (item.get("login", {}).get("uris") or []) if u.get("uri")]


# --------------------------------------------------------------------------- grouping
def group_key(item, args):
    login = item["login"]
    nurls = frozenset(filter(None, (normalize_url(u, args.url_match) for u in urls_of(item))))
    return (
        item.get("organizationId") or "",
        "" if args.ignore_folder else (item.get("folderId") or ""),
        tuple(sorted(item.get("collectionIds") or [])),
        (login.get("username") or "").strip().casefold(),
        login.get("password"),
        nurls,
        # With no URL there is nothing else identifying the site, so require the same name.
        (item.get("name") or "").strip().casefold() if not nurls else None,
    )


def must_keep(item):
    """Things the CLI cannot merge into another item."""
    return bool(item.get("attachments")) or bool(item["login"].get("fido2Credentials"))


def https_count(item):
    return sum(1 for u in urls_of(item) if u.strip().lower().startswith("https://"))


def richness(item):
    login = item["login"]
    return (len(urls_of(item)) + len(item.get("fields") or []) + (1 if login.get("totp") else 0)
            + (1 if (item.get("notes") or "").strip() else 0) + (1 if item.get("favorite") else 0))


# ------------------------------------------------------------------------------ merge
def merge(keeper, dups):
    """Return (merged_item, human-readable change list). Only ever adds information."""
    new = copy.deepcopy(keeper)
    login = new["login"]
    changes = []

    # URLs. Merging https into http is fine; merging http into https is not, so an http URL
    # is skipped when the kept item already has its https twin. https URLs are processed
    # first so a lone http URL is also skipped if another duplicate supplies the https one.
    uris = list(login.get("uris") or [])
    seen = {url_identity(u.get("uri")) for u in uris}

    def covered(ident):
        return ident in seen or (ident.startswith("http://")
                                 and "https://" + ident[len("http://"):] in seen)

    incoming = [u for d in dups for u in (d["login"].get("uris") or []) if (u.get("uri") or "").strip()]
    incoming.sort(key=lambda u: not url_identity(u["uri"]).startswith("https://"))  # stable
    for u in incoming:
        s_ = u["uri"].strip()
        ident = url_identity(s_)
        if not covered(ident):
            uris.append(copy.deepcopy(u))
            seen.add(ident)
            changes.append(f"add URL {clean(s_)}")
    if uris:
        login["uris"] = uris

    # Custom fields
    fields = list(new.get("fields") or [])
    fseen = {(f.get("name"), f.get("value"), f.get("type")) for f in fields}

    def add_field(f, label):
        k = (f.get("name"), f.get("value"), f.get("type"))
        if k not in fseen:
            fields.append(f)
            fseen.add(k)
            changes.append(label)

    for d in dups:
        for f in d.get("fields") or []:
            add_field(copy.deepcopy(f), f'add custom field "{clean(f.get("name"))}"')

    # TOTP: adopt if missing; if two different secrets exist, keep both (hidden field)
    for d in dups:
        t = d["login"].get("totp")
        if not t:
            continue
        if not login.get("totp"):
            login["totp"] = t
            changes.append("add TOTP")
        elif t != login["totp"]:
            add_field({"name": f"TOTP (merged from {d['id'][:8]})", "value": t,
                       "type": FIELD_HIDDEN, "linkedId": None}, "add second TOTP as hidden field")
    if fields:
        new["fields"] = fields

    # Notes
    notes = new.get("notes") or ""
    for d in dups:
        dn = (d.get("notes") or "").strip()
        if dn and dn not in notes:
            notes = (notes + "\n\n" if notes else "") + dn
            changes.append("add notes")
    if notes != (new.get("notes") or ""):
        new["notes"] = notes

    # Favorite / reprompt
    if any(d.get("favorite") for d in dups) and not new.get("favorite"):
        new["favorite"] = True
        changes.append("mark favorite")
    rp = max([new.get("reprompt") or 0] + [d.get("reprompt") or 0 for d in dups])
    if rp != (new.get("reprompt") or 0):
        new["reprompt"] = rp
        changes.append("keep master-password re-prompt")

    # Password history (Bitwarden keeps the latest 5)
    hist = list(new.get("passwordHistory") or [])
    hseen = {(h.get("password"), h.get("lastUsedDate")) for h in hist}
    added = False
    for d in dups:
        for h in d.get("passwordHistory") or []:
            k = (h.get("password"), h.get("lastUsedDate"))
            if k not in hseen:
                hist.append(h)
                hseen.add(k)
                added = True
    if added:
        hist.sort(key=lambda h: h.get("lastUsedDate") or "")
        new["passwordHistory"] = hist[-5:]
        changes.append("add password history")

    return new, changes


def plan(items, args):
    groups = defaultdict(list)
    for it in items:
        if it.get("type") != TYPE_LOGIN or it.get("deletedDate"):
            continue
        if not (it.get("login") or {}).get("password"):
            continue
        groups[group_key(it, args)].append(it)

    plans, skipped = [], []
    for members in groups.values():
        if len(members) < 2:
            continue
        pinned = [m for m in members if must_keep(m)]
        if len(pinned) > 1:
            skipped.append((members, "more than one item has attachments/passkeys, "
                                     "which the CLI cannot merge. Review manually."))
            continue
        keeper = pinned[0] if pinned else max(
            members, key=lambda m: (richness(m), https_count(m), m.get("revisionDate") or ""))
        dups = sorted((m for m in members if m is not keeper),
                      key=lambda m: m.get("revisionDate") or "")
        merged, changes = merge(keeper, dups)
        plans.append({"keeper": keeper, "dups": dups, "merged": merged, "changes": changes})
    return plans, skipped


# ------------------------------------------------------------------------------ report
def describe(it, ctx, tag):
    login = it["login"]
    urls = urls_of(it)
    print(f"    {tag:<7} {it['id']}  \"{clean(it.get('name'))}\"")
    print(f"            folder: {clean(ctx['folders'].get(it.get('folderId'), '(none)'))}"
          f" | org: {clean(ctx['orgs'].get(it.get('organizationId'), '(personal)'))}"
          f" | modified: {(it.get('revisionDate') or '?')[:10]}")
    print(f"            username: {clean(login.get('username')) or '(none)'}"
          f" | password: ******** ({len(login.get('password') or '')} chars, identical)")
    print(f"            URLs: {', '.join(map(clean, urls)) if urls else '(none)'}")
    extras = [n for n, v in (("notes", it.get("notes")), ("custom fields", it.get("fields")),
                             ("TOTP", login.get("totp")), ("attachments", it.get("attachments")),
                             ("passkeys", login.get("fido2Credentials"))) if v]
    if extras:
        print(f"            has: {', '.join(extras)}")


def report(plans, skipped, ctx):
    print(f"\n=== {len(plans)} duplicate group(s) to clean up ===")
    for i, p in enumerate(plans, 1):
        print(f"\n  Group {i}")
        describe(p["keeper"], ctx, "KEEP")
        for d in p["dups"]:
            describe(d, ctx, "TRASH")
        print("            merge into KEEP: " + ("; ".join(p["changes"]) if p["changes"] else "nothing to add"))
    if skipped:
        print(f"\n=== {len(skipped)} group(s) SKIPPED (will not be touched) ===")
        for members, why in skipped:
            print(f"\n  Reason: {why}")
            for m in members:
                describe(m, ctx, "ITEM")
    n = sum(len(p["dups"]) for p in plans)
    print(f"\nTotal: {n} item(s) would be moved to Trash, {sum(1 for p in plans if p['changes'])}"
          " kept item(s) would be updated.")
    return n


# --------------------------------------------------------------------------- execution
class Log:
    def __init__(self, path):
        self.path = path
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        self.f = os.fdopen(fd, "a", encoding="utf-8")

    def write(self, **rec):
        rec["time"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
        self.f.write(json.dumps(rec) + "\n")
        self.f.flush()
        os.fsync(self.f.fileno())


def execute(plans, log):
    deleted = failed = 0
    for p in plans:
        k = p["keeper"]
        try:
            if p["changes"]:
                fresh = json.loads(bw("get", "item", k["id"]))
                if fresh.get("revisionDate") != k.get("revisionDate"):
                    raise BwError("kept item changed since it was listed; re-run to re-plan")
                payload = base64.b64encode(json.dumps(p["merged"]).encode()).decode()
                bw("edit", "item", k["id"], stdin=payload)
                log.write(action="merge", id=k["id"], name=k.get("name"), status="ok",
                          changes=p["changes"])
                print(f"  merged into {k['id']} ({clean(k.get('name'))})")
        except (BwError, json.JSONDecodeError) as e:
            log.write(action="merge", id=k["id"], name=k.get("name"), status="failed", error=str(e))
            print(f"  ! merge failed for {k['id']}: {e}. Its duplicates were NOT deleted.")
            failed += len(p["dups"])
            continue
        for d in p["dups"]:
            try:
                bw("delete", "item", d["id"])  # no --permanent: goes to Trash
                log.write(action="delete", id=d["id"], name=d.get("name"), urls=urls_of(d),
                          kept_id=k["id"], status="ok")
                print(f"  trashed {d['id']} ({clean(d.get('name'))})")
                deleted += 1
            except BwError as e:
                log.write(action="delete", id=d["id"], name=d.get("name"), status="failed", error=str(e))
                print(f"  ! could not trash {d['id']}: {e}")
                failed += 1
    return deleted, failed


def restore(path):
    ids = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            r = json.loads(line)
            if r.get("action") == "delete" and r.get("status") == "ok":
                ids.append((r["id"], r.get("name")))
    if not ids:
        sys.exit("Nothing to restore in that log.")
    print(f"Will restore {len(ids)} item(s) from the Trash:")
    for i, n in ids:
        print(f"  {i}  {clean(n)}")
    if input("Type 'RESTORE' to proceed: ").strip() != "RESTORE":
        sys.exit("Aborted.")
    for i, n in ids:
        try:
            bw("restore", "item", i)
            print(f"  restored {i}")
        except BwError as e:
            print(f"  ! {i}: {e} (already restored, or purged from Trash?)")
    print("Note: information merged into kept items is not removed; restoring is purely additive.")


# -------------------------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser(description="Safely remove duplicate Bitwarden logins.")
    ap.add_argument("--dry-run", action="store_true", help="show the report and exit; change nothing")
    ap.add_argument("--url-match", choices=["full", "host"], default="full",
                    help="full (default): compare host+path; host: compare hostnames only")
    ap.add_argument("--ignore-folder", action="store_true",
                    help="treat items in different folders as potential duplicates "
                         "(never crosses organizations)")
    ap.add_argument("--no-sync", action="store_true", help="skip `bw sync`")
    ap.add_argument("--log", help="path of the action log (default: ./bw-dedupe-<timestamp>.jsonl)")
    ap.add_argument("--restore", metavar="LOG", help="restore items trashed in a previous run")
    args = ap.parse_args()

    if args.restore:
        return restore(args.restore)

    try:
        status = json.loads(bw("status")).get("status")
    except (BwError, json.JSONDecodeError):
        status = None
    if status != "unlocked":
        sys.exit("Vault is not unlocked. Run: export BW_SESSION=\"$(bw unlock --raw)\"")
    if not args.no_sync:
        print("Syncing vault...")
        bw("sync")

    items = json.loads(bw("list", "items"))
    ctx = {"folders": {f["id"]: f["name"] for f in json.loads(bw("list", "folders"))}, "orgs": {}}
    try:
        ctx["orgs"] = {o["id"]: o["name"] for o in json.loads(bw("list", "organizations"))}
    except (BwError, json.JSONDecodeError):
        pass

    plans, skipped = plan(items, args)
    n = report(plans, skipped, ctx)
    if not n:
        print("Nothing to do.")
        return
    if args.dry_run:
        print("\nDry run: no changes were made.")
        return

    print("\nItems go to the Trash (recoverable for 30 days) and every action is logged.")
    if input(f"Type 'DELETE {n}' to proceed: ").strip() != f"DELETE {n}":
        sys.exit("Aborted. No changes were made.")

    logpath = args.log or datetime.now().strftime("bw-dedupe-%Y%m%d-%H%M%S.jsonl")
    log = Log(logpath)
    log.write(action="start", planned_deletes=n, url_match=args.url_match)
    deleted, failed = execute(plans, log)
    log.write(action="finish", deleted=deleted, failed=failed)
    print(f"\nDone: {deleted} trashed, {failed} failed/skipped. Log: {logpath}")
    print(f"Undo with: {sys.argv[0]} --restore {logpath}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit("\nInterrupted.")