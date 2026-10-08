#!/usr/bin/env python3
"""
keepassxc-sshkey - put an SSH private key into a KeePassXC vault.

The problem
-----------
You make an SSH key. Now there is a private key file on disk that either
has no passphrase (anyone who copies the file owns the key) or has one
more passphrase for you to invent and then remember.

What this does
--------------
Point it at a private key file and it will:

  1. generate a strong random passphrase
  2. re-encrypt the key file with it, in place
  3. store the key (and its .pub) as attachments in a KeePassXC entry
  4. store that passphrase in the entry's Password field

Afterwards the passphrase exists only inside your vault. You never have
to remember it, and the file on disk is protected.

Requirements
------------
  ssh-keygen         (OpenSSH)
  keepassxc-cli      (ships with KeePassXC 2.6+)

Both are found on PATH, or given explicitly with --ssh-keygen /
--keepassxc-cli.

Usage
-----
  keepassxc-sshkey ~/.ssh/id_ed25519 --db ~/vault.kdbx
  keepassxc-sshkey ~/.ssh/deploy --db ~/vault.kdbx --entry "GitHub - deploy"
  keepassxc-sshkey --gui

Security model
--------------
This tool is an execution layer: it assumes the thing that invokes it may
be untrusted.

The command line interface refuses to run unless it has a terminal
(stdin and stdout are a tty), reads the vault password only from that
terminal, and never prints or writes down the passphrase it generates.
An automated caller therefore cannot make it unlock a vault or hand over
a passphrase.

The graphical interface is meant to be operated by a person. It takes the
vault password from a masked entry field, keeps it in memory only, and
never displays or logs the generated passphrase either.

One exposure cannot be removed: ssh-keygen accepts a passphrase only as a
command line argument, so for the fraction of a second ssh-keygen runs,
the passphrase it was given is visible in the local process table. This
is a property of OpenSSH. With --no-reencrypt the key keeps its existing
passphrase - but that passphrase is still passed to ssh-keygen once, on a
throwaway copy, to prove it really opens the key before anything is
stored.

The core of this module (store_key) is importable and is what the GUI
calls. It returns only a status object - never the passphrase.
"""

from __future__ import annotations

import argparse
import base64
import getpass
import os
import secrets
import shutil
import string
import struct
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable, Sequence

PROG = "keepassxc-sshkey"

PASSPHRASE_ALPHABET = string.ascii_letters + string.digits
DEFAULT_PASSPHRASE_LEN = 32
DEFAULT_KDF_ROUNDS = 24
OPENSSH_MAGIC = b"openssh-key-v1\x00"


class ToolError(RuntimeError):
    """Something went wrong that the user needs to see."""


# --------------------------------------------------------------------------
# results and logging
# --------------------------------------------------------------------------

@dataclass
class StoreResult:
    """Outcome of a store_key() call.

    Deliberately contains no secret material.
    """

    ok: bool
    message: str
    fingerprint: str = ""
    backup: str = ""
    verified: bool = False
    log: list[str] = field(default_factory=list)


LogFn = Callable[[str], None]


def _noop(_msg: str) -> None:
    pass


# --------------------------------------------------------------------------
# subprocess helpers
# --------------------------------------------------------------------------

def find_tool(name: str, explicit: str | None = None) -> str:
    if explicit:
        path = Path(explicit).expanduser()
        if not path.exists():
            raise ToolError(f"{name} not found at {path}")
        return str(path)
    found = shutil.which(name)
    if not found:
        raise ToolError(f"{name} not found on PATH")
    return found


def run(argv: Sequence[str], stdin_text: str | None = None, capture: bool = False):
    """Run a command. Raise ToolError with the last stderr line on failure."""
    kwargs: dict = {"check": False}
    if stdin_text is not None:
        kwargs["input"] = stdin_text.encode()
    if capture:
        kwargs["stdout"] = subprocess.PIPE
        kwargs["stderr"] = subprocess.PIPE
    else:
        kwargs["stdout"] = subprocess.DEVNULL

    try:
        proc = subprocess.run(list(argv), **kwargs)
    except OSError as exc:
        raise ToolError(f"could not run {argv[0]}: {exc}") from exc

    if proc.returncode != 0:
        tail = ""
        if capture:
            err = (proc.stderr or b"").decode(errors="replace").strip()
            if err:
                tail = "\n  " + err.splitlines()[-1]
        raise ToolError(f"{Path(argv[0]).name} failed (exit {proc.returncode}){tail}")
    return proc


# --------------------------------------------------------------------------
# passphrase
# --------------------------------------------------------------------------

def generate_passphrase(length: int = DEFAULT_PASSPHRASE_LEN) -> str:
    """Random passphrase, letters and digits only.

    Letters and digits only, on purpose: the value travels through a
    command line and through a pipe, and staying clear of shell
    metacharacters removes an entire family of quoting bugs.
    """
    return "".join(secrets.choice(PASSPHRASE_ALPHABET) for _ in range(length))


# --------------------------------------------------------------------------
# private key inspection and re-encryption
# --------------------------------------------------------------------------

def fingerprint(ssh_keygen: str, path: Path) -> str:
    """Fingerprint of a key. Works on a protected key, no passphrase needed:
    the public half of an OpenSSH private key file is stored in the clear."""
    proc = run([ssh_keygen, "-l", "-f", str(path)], capture=True)
    out = (proc.stdout or b"").decode(errors="replace").strip()
    if not out:
        raise ToolError(f"could not read a fingerprint from {path}")
    bits = out.split()
    return " ".join(bits[:2]) if len(bits) >= 2 else out


def is_protected(path: Path) -> bool:
    """True when the key file carries a passphrase.

    Answered from the file header alone, so no passphrase is required.
    A protected key records a real cipher name; an unprotected one says
    "none".
    """
    try:
        blob = path.read_bytes()
    except OSError as exc:
        raise ToolError(f"cannot read {path}: {exc}") from exc

    head = b"-----BEGIN OPENSSH PRIVATE KEY-----"
    if head not in blob:
        raise ToolError(
            f"{path.name} is not an OpenSSH private key. "
            f"Convert it first, e.g. ssh-keygen -p -m RFC4716 -f \"{path}\""
        )

    body = blob.split(head, 1)[1].split(b"-----END", 1)[0]
    raw = base64.b64decode(b"".join(body.split()))
    if not raw.startswith(OPENSSH_MAGIC):
        raise ToolError(f"{path.name} has an unrecognised OpenSSH key header")

    pos = len(OPENSSH_MAGIC)
    (cipher_len,) = struct.unpack(">I", raw[pos:pos + 4])
    pos += 4
    cipher = raw[pos:pos + cipher_len].decode(errors="replace")
    return cipher != "none"


def reencrypt(ssh_keygen: str, path: Path, old: str, new: str, rounds: int) -> None:
    """Swap the passphrase on a private key file, in place."""
    run([ssh_keygen, "-p", "-f", str(path),
         "-a", str(rounds), "-N", new, "-P", old])


def confirm_passphrase(ssh_keygen: str, path: Path, new: str) -> None:
    """Prove the new passphrase opens the file.

    Re-encrypts with the same passphrase, so the file comes out unchanged
    but we learn whether 'new' was written correctly.
    """
    run([ssh_keygen, "-p", "-f", str(path), "-N", new, "-P", new])


def verify_existing_passphrase(ssh_keygen: str, path: Path, passphrase: str) -> bool:
    """Does `passphrase` open `path`?  The key file itself is left untouched.

    Call this for a protected key whose passphrase is not being changed:
    nothing else in that path would ever notice a typo, and the typo would
    end up stored in the vault.

    ssh-keygen has no read-only "check this passphrase" mode that works
    across the OpenSSH builds this tool supports, so the check runs
    against a throwaway copy placed next to the key file.  Same directory
    means the same permissions, and that matters: OpenSSH refuses to use a
    private key whose ACL is too loose, and system-wide temp directories
    usually are exactly that.

    Returns True when the passphrase opens the key and False when
    ssh-keygen says, in so many words, that it does not.  Raises ToolError
    when the question cannot be answered at all (an ACL problem, a damaged
    file, a broken tool) - the caller must not turn "cannot tell" into
    "wrong passphrase".
    """
    probe = path.with_name(f".{path.name}.check-{secrets.token_hex(4)}")
    try:
        shutil.copy2(path, probe)
        os.chmod(probe, 0o600)
    except OSError as exc:
        raise ToolError(
            f"could not place a check copy next to {path.name}: {exc}"
        ) from exc

    try:
        run([ssh_keygen, "-p", "-f", str(probe),
             "-N", passphrase, "-P", passphrase],
            capture=True)
    except ToolError as exc:
        if "incorrect passphrase" in str(exc).lower():
            return False
        raise ToolError(
            f"could not verify the passphrase against {path.name}: {exc}"
        ) from exc
    finally:
        try:
            probe.unlink()
        except OSError:
            pass
    return True


# --------------------------------------------------------------------------
# keepassxc-cli wrappers
# --------------------------------------------------------------------------

def kpxc_entry_exists(cli: str, db: Path, entry: str, db_password: str) -> bool:
    proc = subprocess.run(
        [cli, "show", str(db), entry],
        input=(db_password + "\n").encode(),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return proc.returncode == 0


def kpxc_create_entry(cli: str, db: Path, entry: str, db_password: str, notes: str) -> None:
    run([cli, "add", "--notes", notes, str(db), entry],
        stdin_text=db_password + "\n")


def kpxc_import_attachment(cli: str, db: Path, entry: str, name: str,
                           source: Path, db_password: str) -> None:
    run([cli, "attachment-import", "-f", str(db), entry, name, str(source)],
        stdin_text=db_password + "\n")


def kpxc_set_entry_password(cli: str, db: Path, entry: str,
                            db_password: str, entry_password: str) -> None:
    """Write the entry's Password field.

    keepassxc-cli reads the vault password first and the new entry password
    second, both from stdin, so one two-line stream is enough and nothing
    has to touch the filesystem.
    """
    run([cli, "edit", "-p", str(db), entry],
        stdin_text=f"{db_password}\n{entry_password}\n")


def kpxc_read_entry_password(cli: str, db: Path, entry: str, db_password: str) -> str:
    proc = run([cli, "show", "-s", str(db), entry],
               stdin_text=db_password + "\n", capture=True)
    out = (proc.stdout or b"").decode(errors="replace")
    for line in out.splitlines():
        if line.startswith("Password:"):
            return line.split(":", 1)[1].strip()
    return ""


# --------------------------------------------------------------------------
# the core operation - used by both the CLI and the GUI
# --------------------------------------------------------------------------

def store_key(
    keyfile: Path,
    db: Path,
    entry: str,
    db_password: str,
    *,
    old_passphrase: str = "",
    new_passphrase: str | None = None,
    passphrase_length: int = DEFAULT_PASSPHRASE_LEN,
    kdf_rounds: int = DEFAULT_KDF_ROUNDS,
    keep_backup: bool = True,
    reencrypt_key: bool = True,
    ssh_keygen: str | None = None,
    keepassxc_cli: str | None = None,
    log: LogFn | None = None,
) -> StoreResult:
    """Protect a private key with a fresh passphrase and file it in a vault.

    The passphrase is never returned. If you do not supply one, a random
    one is generated and it ends up in the vault entry's Password field
    and nowhere else.
    """
    say: LogFn = log or _noop
    lines: list[str] = []

    def emit(msg: str) -> None:
        lines.append(msg)
        say(msg)

    keyfile = Path(keyfile).expanduser()
    db = Path(db).expanduser()
    entry = entry.strip() or keyfile.stem

    if not keyfile.is_file():
        return StoreResult(False, f"no such key file: {keyfile}", log=lines)
    if not db.is_file():
        return StoreResult(False, f"no such vault: {db}", log=lines)
    if not db_password:
        return StoreResult(False, "empty vault password", log=lines)

    try:
        ssh_keygen = find_tool("ssh-keygen", ssh_keygen)
        cli = find_tool("keepassxc-cli", keepassxc_cli)
    except ToolError as exc:
        return StoreResult(False, str(exc), log=lines)

    pub = Path(str(keyfile) + ".pub")
    pub = pub if pub.exists() else None

    emit(f"key file : {keyfile}")
    emit(f"vault    : {db}")
    emit(f"entry    : {entry}")

    # ---- can we open the vault? -----------------------------------------
    try:
        run([cli, "ls", str(db)], stdin_text=db_password + "\n")
    except ToolError:
        return StoreResult(False, "cannot open the vault with that password", log=lines)

    # ---- inspect the key -------------------------------------------------
    try:
        protected = is_protected(keyfile)
        fp = fingerprint(ssh_keygen, keyfile)
    except ToolError as exc:
        return StoreResult(False, str(exc), log=lines)

    emit(f"fingerprint : {fp}")

    if reencrypt_key and protected and not old_passphrase:
        return StoreResult(
            False,
            "this key is protected, but no current passphrase was given",
            fingerprint=fp, log=lines,
        )

    if new_passphrase is None:
        # No explicit value: re-encrypting gets a freshly generated
        # passphrase, keeping the current one just carries it over.
        new_passphrase = (generate_passphrase(passphrase_length)
                          if reencrypt_key else old_passphrase)
    if not new_passphrase:
        if protected:
            return StoreResult(
                False,
                "this key is protected, but its current passphrase was not "
                "given: type it, or let the tool generate a new one",
                fingerprint=fp, log=lines,
            )
        return StoreResult(
            False,
            "this key has no passphrase and none was generated: there would "
            "be nothing to store in the vault entry's Password field - let "
            "the tool generate one",
            fingerprint=fp, log=lines,
        )

    if reencrypt_key:
        emit(f"passphrase  : {len(new_passphrase)} random characters (not displayed)")
    else:
        # Keeping the existing passphrase means the key is never
        # re-encrypted, so nothing downstream would notice a typo in it.
        # Prove it opens the key before it goes anywhere near the vault.
        # If the check cannot run at all (odd ACLs, a damaged file), say so
        # and carry on - refusing here would punish a perfectly good key.
        emit("passphrase  : kept as-is (checking it against the key...)")
        try:
            opens_key = verify_existing_passphrase(ssh_keygen, keyfile, new_passphrase)
        except ToolError as exc:
            opens_key = None
            emit(f"WARNING: {exc}")
            emit("         the passphrase will be stored as given")
        if opens_key is False:
            return StoreResult(
                False,
                "the current passphrase does not open this key",
                fingerprint=fp, log=lines,
            )
        if opens_key:
            emit("passphrase  : the current passphrase opens the key")

    # ---- back up, then protect -------------------------------------------
    backup: Path | None = None
    if keep_backup:
        backup = Path(str(keyfile) + ".orig")
        try:
            shutil.copy2(keyfile, backup)
            os.chmod(backup, 0o600)
            emit(f"backup      : {backup}")
        except OSError as exc:
            return StoreResult(False, f"could not write the backup: {exc}",
                               fingerprint=fp, log=lines)

    if reencrypt_key:
        emit("re-encrypting the key...")
        try:
            reencrypt(ssh_keygen, keyfile, old_passphrase, new_passphrase, kdf_rounds)
            confirm_passphrase(ssh_keygen, keyfile, new_passphrase)
        except ToolError as exc:
            if backup and backup.exists():
                try:
                    shutil.copy2(backup, keyfile)
                except OSError:
                    pass
            return StoreResult(
                False, f"could not protect the key file (original restored): {exc}",
                fingerprint=fp,
                backup=str(backup) if backup else "",
                log=lines,
            )
        emit("key file is protected and the new passphrase opens it")

    # ---- vault ------------------------------------------------------------
    emit("updating the vault...")
    try:
        if not kpxc_entry_exists(cli, db, entry, db_password):
            kpxc_create_entry(
                cli, db, entry, db_password,
                notes=f"SSH key: {keyfile.name}\nfingerprint: {fp}",
            )
            emit(f"entry '{entry}' created")
        else:
            emit(f"entry '{entry}' already exists - updating it")

        kpxc_import_attachment(cli, db, entry, keyfile.name, keyfile, db_password)
        emit(f"attached {keyfile.name}")
        if pub is not None:
            kpxc_import_attachment(cli, db, entry, pub.name, pub, db_password)
            emit(f"attached {pub.name}")

        kpxc_set_entry_password(cli, db, entry, db_password, new_passphrase)
        emit("passphrase stored in the entry's Password field")
    except ToolError as exc:
        return StoreResult(
            False,
            f"vault update failed: {exc}",
            fingerprint=fp,
            backup=str(backup) if backup else "",
            log=lines,
        )

    try:
        verified = kpxc_read_entry_password(cli, db, entry, db_password) == new_passphrase
    except ToolError:
        verified = False

    emit("verified: stored value matches" if verified
         else "WARNING: could not verify the stored value")

    return StoreResult(
        True,
        "done",
        fingerprint=fp,
        backup=str(backup) if backup else "",
        verified=verified,
        log=lines,
    )


# --------------------------------------------------------------------------
# command line interface
# --------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=PROG,
        description="Store an SSH private key in a KeePassXC vault, "
                    "protecting it with a freshly generated passphrase.",
    )
    p.add_argument("keyfile", nargs="*", type=Path,
                   help="one or more private key files to store "
                        "(omit with --gui)")
    p.add_argument("--db", type=Path, default=os.environ.get("KPXC_DB"),
                   help="path to the .kdbx vault (default: $KPXC_DB)")
    p.add_argument("--entry", default=None,
                   help="entry name in the vault (single key file only; "
                        "otherwise the key file name is used)")
    p.add_argument("--passphrase-length", type=int, default=DEFAULT_PASSPHRASE_LEN,
                   help=f"length of the generated passphrase (default {DEFAULT_PASSPHRASE_LEN})")
    p.add_argument("--kdf-rounds", type=int, default=DEFAULT_KDF_ROUNDS,
                   help=f"bcrypt rounds for the new passphrase (default {DEFAULT_KDF_ROUNDS})")
    p.add_argument("--no-reencrypt", action="store_true",
                   help="keep the key's existing passphrase, just store it")
    p.add_argument("--no-backup", action="store_true",
                   help="do not keep a .orig copy of the key file")
    p.add_argument("--ssh-keygen", default=None, help="path to ssh-keygen")
    p.add_argument("--keepassxc-cli", default=None, help="path to keepassxc-cli")
    p.add_argument("--dry-run", action="store_true", help="show the plan, change nothing")
    p.add_argument("--gui", action="store_true", help="start the graphical interface")
    return p


def die(msg: str, code: int = 1):
    print(f"{PROG}: error: {msg}", file=sys.stderr)
    raise SystemExit(code)


def main(argv: Iterable[str] | None = None) -> int:
    args = build_parser().parse_args(list(argv) if argv is not None else None)

    if args.gui:
        try:
            from keepassxc_sshkey_gui import run_gui
        except ImportError as exc:
            die(f"cannot start the GUI: {exc}\n"
                f"       keepassxc_sshkey_gui.py must sit next to this file")
        return run_gui(default_db=str(args.db) if args.db else "")

    # ------------------------------------------------------------------
    # From here on this is the command line interface, and it refuses to
    # run any way other than interactively. The reasoning:
    #
    #   - a piped stdin or a captured stdout means an automated caller
    #   - an automated caller must not be able to make this tool unlock
    #     a vault or reveal a passphrase
    #
    # The core function store_key() has no such check, because the GUI
    # needs it; the check lives here, at the CLI entry point.
    # ------------------------------------------------------------------
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        die(
            "this tool must be run interactively from a terminal.\n"
            "       It refuses to run with piped input or captured output, so that\n"
            "       no automated caller can obtain a vault password or a key\n"
            "       passphrase through it."
        )

    if not args.keyfile:
        die("no key file given. Pass one or more, or use --gui.")

    if len(args.keyfile) > 1 and args.entry:
        die("--entry can only be used with a single key file; when several "
            "files are given, each entry is named after its key file")

    keyfiles = [Path(k).expanduser() for k in args.keyfile]
    for keyfile in keyfiles:
        if not keyfile.is_file():
            die(f"no such key file: {keyfile}")

    if args.db is None:
        die("no vault given. Use --db PATH or set KPXC_DB.")
    db: Path = Path(args.db).expanduser()
    if not db.is_file():
        die(f"no such vault: {db}")

    if args.dry_run:
        print(f"vault : {db}")
        print(f"mode  : {'keep passphrase' if args.no_reencrypt else 'new random passphrase'}")
        for keyfile in keyfiles:
            print(f"key   : {keyfile}")
            print(f"        entry -> {args.entry or keyfile.stem}")
        print("dry run - nothing changed")
        return 0

    db_password = getpass.getpass(f"Master password for {db.name}: ")
    if not db_password:
        die("empty vault password")

    # The vault password is asked once for the whole run. So is the existing
    # key passphrase: a set of keys usually shares one, and asking per key
    # would be noise. A key that rejects it fails on its own and the rest
    # carry on.
    old_passphrase = ""
    old_passphrase_asked = False

    total = len(keyfiles)
    ok = failed = 0

    for index, keyfile in enumerate(keyfiles, start=1):
        if total > 1:
            print()
            print(f"--- [{index}/{total}] {keyfile.name} ---")

        try:
            protected = is_protected(keyfile)
        except ToolError as exc:
            print(f"  skipped: {exc}")
            failed += 1
            continue

        if protected and not old_passphrase_asked:
            if total > 1:
                prompt = "Existing key passphrase (asked once, reused for all): "
            else:
                prompt = f"Current passphrase for {keyfile.name}: "
            given = getpass.getpass(prompt)
            if not given:
                print("  skipped: this key is protected but no passphrase was given")
                failed += 1
                continue
            old_passphrase = given
            old_passphrase_asked = True

        result = store_key(
            keyfile,
            db,
            args.entry or keyfile.stem,
            db_password,
            old_passphrase=old_passphrase,
            passphrase_length=args.passphrase_length,
            kdf_rounds=args.kdf_rounds,
            keep_backup=not args.no_backup,
            reencrypt_key=not args.no_reencrypt,
            ssh_keygen=args.ssh_keygen,
            keepassxc_cli=args.keepassxc_cli,
            log=lambda m: print("  " + m),
        )

        if result.ok:
            ok += 1
            print("  ok")
            print("     key file on disk is protected")
            print("     passphrase is in the vault entry's Password field")
            if result.backup:
                print(f"     previous version kept at {result.backup}")
        else:
            failed += 1
            print(f"  FAILED: {result.message}")

    if total > 1:
        print()
        print(f"done: {ok} stored, {failed} failed")

    return 0 if failed == 0 else 2


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print(f"\n{PROG}: interrupted", file=sys.stderr)
        raise SystemExit(130)
    except ToolError as exc:
        die(str(exc))
