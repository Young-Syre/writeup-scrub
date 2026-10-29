# writeup-scrub

[![tests](https://github.com/Young-Syre/writeup-scrub/actions/workflows/tests.yml/badge.svg)](https://github.com/Young-Syre/writeup-scrub/actions/workflows/tests.yml)
[![python](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![license](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![dependencies](https://img.shields.io/badge/dependencies-none-lightgrey.svg)](pyproject.toml)

Sanitise security writeups and CTF notes before you publish them.

Writeups get published straight out of someone's notes, and the notes leak:
platform flags (against the rules on most platforms), an API token that was
sitting in the terminal scrollback, the author's home directory and username,
their VPN address, their personal email, and the private scaffolding of an
Obsidian vault. `writeup-scrub` is a pattern-based pass that catches the
routine ones, as a report you read, a diff you approve, or a gate that fails
your CI before a flag reaches a public branch.

Every rule here exists because the mistake it catches is one people make
repeatedly and notice late — after a push, in someone else's pull request, or
when a platform's moderator gets there first. WS001 is built the way it is for
that reason: the expensive case is not failing to spot a flag, it is redacting
a hash that was the whole point of the writeup.

---

## The flag-versus-hash distinction

This is the subtle part, and it is the reason the tool exists rather than a
`grep -E '[0-9a-f]{32}'`.

A platform flag is 32 hex characters. So is an NTLM hash, an MD5 checksum, an
MD4 digest, an ETag and the empty-LM-hash constant — and those are *legitimate
technical content* in a retired-machine writeup. Blanket-redacting every 32-hex
string does not sanitise the writeup, it destroys it.

WS001 decides per match, using the nearest label:

```markdown
User flag: 0123456789abcdef0123456789abcdef      ->  redacted
Root flag: fedcba9876543210fedcba9876543210      ->  redacted
user_flag: 11112222333344445555666677778888      ->  redacted

NTLM hash: 8846f7eaee8fb117ad06bdd830b7586c      ->  kept
md5sum output: c4ca4238a0b923820dcc509a6f75849b  ->  kept
Administrator:500:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::
                                                  ->  kept (both of them)
```

Resolution order for each candidate:

1. **the text before it on the line** — nearest keyword wins
2. **the text after it on the line**
3. **the preceding lines**, bounded by the enclosing code fence

so a flag read out of a file inside a code block is caught:

````markdown
```
$ cat /root/root.txt
aaaa1111bbbb2222cccc3333dddd4444      <- redacted (flag-read command above it)
```

```
$ md5sum ligolo-ng.tar.gz
c4ca4238a0b923820dcc509a6f75849b      <- kept (hash command above it)
```
````

Nearest label wins, which is what makes the mixed sentence come out right:

```markdown
I grabbed the user flag only after cracking the NTLM hash
8846f7eaee8fb117ad06bdd830b7586c, which gave me the service password.
```

Both "flag" and "hash" appear; "hash" is closer, so the value survives.

Braced flags are unambiguous and always redacted, case-insensitively —
`HTB{...}`, `htb{...}`, `thm{...}`, `Flag{...}`, `PICOCTF{...}`, `Key{...}`.
Platforms are inconsistent about case and writeups are worse, and a THM or
picoCTF flag is words rather than hex, so nothing downstream would catch one
that slipped through here. Well-known constants (the empty LM and NT hashes,
the MD5 of the empty string) are never redacted, whatever the context claims.

**The deliberate boundary:** a bare 32-hex string with no context anywhere near
it is genuinely ambiguous, so it is kept and warned about rather than redacted.
The warning fires wherever the value sits — `then I pasted <flag> into the box`
is as unlabelled as a hex string on its own line. *Redaction* of an unlabelled
value is narrower: `redact_bare_hex = true` only redacts one alone on a line,
because a 32-hex string in running text is usually a hash. Set
`warn_on_bare_hex = false` to silence the warning. A `md5sum`-shaped line
(digest, two spaces, filename) is read as a checksum and neither redacted nor
warned about.

Zero-width and bidirectional characters are stripped from every line before any
rule runs, inside code fences as well as outside. A `U+200B` in the middle of a
flag renders as the whole flag but reads to a regex as two short hex runs, so a
value carrying one would otherwise publish intact. A 32-hex string embedded in
a longer hex run (`<32hex>deadbeef`) is still not matched — the boundary
assertions require it to stand alone.

The flag-vs-hash behaviour is tested in both directions — a positive fixture
where every flag must be redacted and a negative fixture where every hash must
survive, plus the nearest-label and fence-context cases above.

---

## Install

```bash
pip install git+https://github.com/Young-Syre/writeup-scrub
```

Or from a clone:

```bash
git clone https://github.com/Young-Syre/writeup-scrub && cd writeup-scrub
pip install .
```

Python 3.11+ and no runtime dependencies. The core logic and the retirement
check both use only the standard library.

---

## Usage

```bash
writeup-scrub init                       # write a commented .writeup-scrub.toml
writeup-scrub rules                      # list the rules and severities

writeup-scrub scan  writeups/            # report only; the publication gate
writeup-scrub diff  writeups/Box.md      # see exactly what would change
writeup-scrub clean writeups/ --out public/
```

`scan` on a real writeup, with this `.writeup-scrub.toml` in the repo root:

```toml
[rules.WS003]
users = ["david"]
[rules.WS005]
strip_cidrs = ["10.10.14.0/24"]
```

```
Blackfield.md
  WS006 low      line 3     frontmatter key 'tags' removed
      -> <line removed>
  WS006 low      line 4     frontmatter key 'status' removed
      -> <line removed>
  WS006 low      line 9     wikilink converted to text
      -> Notes drafted in the vault, see Kerberos Delegation Notes.
  WS003 medium   line 14    operator home directory rewritten
      -> $ nmap -sC -sV -p- 10.10.10.192 -oA /home/operator/htb/blackfield/nmap/full
  WS005 high     line 17    operator address redacted
      -> My tun0 address was [REDACTED: operator address] for this session.
  WS001 critical line 33    platform flag redacted
      -> [REDACTED: platform flag]
  WS001 critical line 36    platform flag redacted
      -> Root flag: [REDACTED: platform flag]
  WS002 critical line 38    AWS access key id redacted
      -> Reported to [REDACTED: email] and AWS_KEY=[REDACTED: secret] was in env.
  WS004 medium   line 38    email address redacted
      -> Reported to [REDACTED: email] and AWS_KEY=[REDACTED: secret] was in env.
  WS007 info     line 40    scratch marker 'TODO' left in the text
  (+7 markdown hygiene change(s))

1 file(s) · 9 redaction(s) (3 critical) · 1 warning(s) · 7 hygiene change(s)
```

on stderr, with exit code 1:

```
writeup-scrub: publication gate FAILED: 3 finding(s) at or above critical (WS001, WS002)
```

Note what survived: the target's address `10.10.10.192`, the full nmap flags,
the `TODO` (reported, not deleted), and the NTLM hashes further down the file.
The operator's tunnel address, home directory and both flags did not. That
input file is `tests/fixtures/writeup_end_to_end.md`, so you can reproduce it.

### Modes

| mode | what it does |
| --- | --- |
| `scan` | reports; exits 1 if anything at or above `--fail-on` (default `critical`) would fire. Never writes. |
| `clean` | writes sanitised copies to `--out DIR`. Needs an explicit `--in-place` to touch the originals. |
| `diff` | unified diff of the proposed changes. Writes nothing. |
| `init` | writes a commented `.writeup-scrub.toml`. |
| `rules` | lists rule ids, severities and what each one preserves. |

### Exit codes

| code | meaning |
| --- | --- |
| 0 | nothing at or above the threshold |
| 1 | the publication gate failed |
| 2 | usage, configuration or I/O error |
| 3 | the retirement check could not be completed, or the machine is not retired |

`clean` never writes in place unless you say so. With neither `--out` nor
`--in-place` it refuses and changes nothing, and if `--out` happens to resolve
to the input file itself it refuses that too rather than silently overwriting.

---

## Redaction rules

Each rule has a stable id, is independently toggleable, and reports the file and
line of everything it changed.

| id | severity | catches | deliberately preserves |
| --- | --- | --- | --- |
| **WS001** | critical | 32-hex strings in flag context (`User flag:`, `root.txt` output, flag-submission blocks) and braced flags like `HTB{...}` | NTLM/NT/LM hashes, md5 checksums, MD4 digests, UUIDs, ETags — any 32-hex whose nearest label is a hash |
| **WS002** | critical | AWS `AKIA`/`ASIA`, Google `AIza`, Stripe `sk_live`/`rk_live`, GitHub `ghp_`/`gho_`/`ghu_`/`ghs_`/`github_pat_`, Slack `xox[baprs]-`, SendGrid `SG.`, OpenAI `sk-`, Twilio `SK`, JWTs, PEM private-key bodies | the surrounding command and the `BEGIN`/`END` key banners, so the reader still sees a key was there; target session cookies unless `detect_session_cookies` is on |
| **WS003** | medium | `/home/<user>`, `/Users/<user>`, `C:\Users\<user>` | the entire trailing path, and `preserve_users` (Windows `Public`/`Default`/`Administrator` are target-side by default) |
| **WS004** | medium | email addresses and phone numbers | in-universe addresses (`admin@target.htb`, `*.local`, `example.com`), anything in `preserve_addresses`, and `user@host` shapes that are not emails (`svc@10.10.10.192`, an SSH key's `user@target` comment) |
| **WS005** | high | IPv4 addresses inside the CIDRs you list in `strip_cidrs` | HTB lab ranges (`10.10.0.0/16`, `10.129.0.0/16`), RFC1918 and loopback — and strips nothing at all until you configure a range |
| **WS006** | low | configured YAML frontmatter keys, `[[wikilinks]]`, Obsidian callouts, `%%comments%%` | frontmatter keys you did not list, the visible text of every wikilink, the callout body |
| **WS007** | info | `TODO`/`FIXME`/`XXX`/`HACK`, hint-seeking asides ("ask in discord", "got hint from"), empty sections | everything — WS007 only warns, it never edits |

WS007 is deliberately a reporter. Silently deleting a half-finished thought is
worse than publishing it, because you would never know the section was empty.

### Detail worth knowing

**WS002** bounds the search for a PEM key body by shape — base64 lines, RFC
1421 headers, and the blank line between them. A writeup quite reasonably
contains a `-----BEGIN OPENSSH PRIVATE KEY-----` line with no matching `END`,
because someone pasted the first line to show the key was unencrypted. Scanning
forward to the `END` banner and treating everything in between as key material
deletes the rest of the file in that case, so the scan stops at the first line
that is not key-shaped. A banner with no key body after it is reported as a
`medium` warning and changes nothing.

**WS003** rewrites *every* home directory by default, including a target
machine's `/home/svc_apache`. In a writeup repository you almost always want:

```toml
[rules.WS003]
users = ["yourname"]
```

**WS005** strips nothing until you name a range, and resolves overlaps by
longest prefix. A strip of `10.10.14.0/24` beats the default preserve of
`10.10.0.0/16`, so your tunnel address goes and the box at `10.10.11.3` stays:

```toml
[rules.WS005]
strip_cidrs = ["10.10.14.0/24", "10.10.16.0/24"]
```

**WS006** maps Obsidian callouts onto the five GitHub alert types, so
`> [!warning] Careful` becomes `> [!NOTE]`-style markup GitHub actually renders:

```markdown
> [!WARNING]
> **Careful**
```

---

## Markdown hygiene

A second pass that is about rendering, not leaks. Reported with `MD-*` ids at
`info` severity, so it never fails the gate:

- closes unterminated code fences
- adds a language hint to bare fences by sniffing the content (`bash`, `python`,
  `powershell`, `sql`, `http`, `json`, else `text`)
- normalises heading levels so there is exactly one H1
- strips trailing whitespace (outside code blocks, which are left byte for byte)
- collapses runs of blank lines

Turn it off with `--no-hygiene` or `[hygiene] enabled = false`.

---

## Retirement check (opt-in, the only networked feature)

Publishing a writeup for an active machine breaks the rules on Hack The Box and
most other platforms. `--check-retired` verifies the machine is in the retired
list before anything else runs:

```bash
export HTB_TOKEN=...        # your own App Token
writeup-scrub scan writeups/Blackfield.md --check-retired --machine Blackfield
```

**No token is bundled, and the tool reads one only from the environment**
(`HTB_TOKEN`, or `--token-env OTHER_VAR`). Create an App Token under your own
HTB profile settings. With `--machine` omitted, the machine name is taken from
the first filename and printed so you can see what was checked.

The check **fails loudly** rather than defaulting to "retired". A missing token,
an unreachable API, a non-JSON response, a changed response shape or an empty
list all exit 3 with the reason. "Not in the retired list" is reported as its
own error — the tool never treats a failed lookup as permission to publish.

Every other mode and rule is entirely offline, as is the whole test suite.

### Adding a platform adapter

Only the HTB adapter ships. To add another:

1. subclass `PlatformAdapter` in `writeup_scrub/platforms/`, setting `name`,
   `token_env` and `docs`
2. implement `retired_machines(timeout) -> list[str]`, raising
   `RetirementCheckError` on anything that is not a confident answer
3. register it in `ADAPTERS` in `writeup_scrub/platforms/__init__.py`

`PlatformAdapter.check()` handles name matching. The constructor takes a
`fetcher(url, headers, timeout) -> bytes`, which is how the tests mock the
network — keep that seam and your adapter stays testable offline.

---

## Using it as a gate

### Pre-commit hook

`.git/hooks/pre-commit`:

```bash
#!/usr/bin/env bash
set -euo pipefail

staged=$(git diff --cached --name-only --diff-filter=ACM | grep -E '\.(md|markdown)$' || true)
[ -z "$staged" ] && exit 0

if ! writeup-scrub scan $staged; then
    echo
    echo "Commit blocked. Review with:  writeup-scrub diff $staged"
    echo "Then clean with:              writeup-scrub clean <file> --out public/"
    exit 1
fi
```

```bash
chmod +x .git/hooks/pre-commit
```

Or as a [pre-commit](https://pre-commit.com) hook:

```yaml
repos:
  - repo: local
    hooks:
      - id: writeup-scrub
        name: writeup-scrub
        entry: writeup-scrub scan
        language: system
        types: [markdown]
```

### GitHub Actions

```yaml
name: publication-gate

on: [push, pull_request]

jobs:
  scrub:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - run: pip install git+https://github.com/Young-Syre/writeup-scrub

      # Exits 1 on any CRITICAL redaction: a flag or a live secret in a writeup
      # fails the build before it can be merged.
      - run: writeup-scrub scan writeups/ --report scrub-report.json

      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: scrub-report
          path: scrub-report.json
```

---

## Configuration

`writeup-scrub init` writes a commented `.writeup-scrub.toml`. It is discovered
from the working directory upwards, or passed with `--config`.

```toml
[rules.WS001]
enabled = true
marker = "[REDACTED: platform flag]"
context_lines = 5            # how far back flag/hash context may reach
redact_bare_hex = false      # redact unlabelled 32-hex alone on a line
warn_on_bare_hex = true
redact_braced_flags = true
extra_flag_keywords = []     # add your own context words
extra_hash_keywords = []
never_redact = [...]         # constants that are never flags

[rules.WS002]
detect_jwts = true
detect_private_keys = true
detect_session_cookies = false   # target cookies are usually the finding
disabled_patterns = []           # e.g. ["openai"]

[rules.WS003]
placeholder = "operator"
users = []                   # empty = every home directory; name yours instead
preserve_users = ["Public", "Default", "Administrator", ...]

[rules.WS004]
detect_emails = true
detect_phones = true
preserve_addresses = []      # your public contact address
preserve_domains = ["htb", "thm", "local", "example.com", ...]

[rules.WS005]
strip_cidrs = []             # your tunnel ranges; nothing is stripped until set
preserve_cidrs = ["10.10.0.0/16", "10.129.0.0/16", ...]

[rules.WS006]
drop_frontmatter_keys = ["tags", "status", "type", "aliases"]
wikilink_mode = "text"       # or "link" for [Alias](Page.md)
convert_callouts = true
strip_comments = true

[rules.WS007]
markers = ["TODO", "FIXME", "XXX", "HACK", "WIP", "NOTE TO SELF"]
phrases = ["ask in discord", "got hint from", ...]
warn_empty_sections = true

[hygiene]
enabled = true
max_consecutive_blank_lines = 1

[retirement]
platform = "htb"
timeout = 15.0
```

Configuration is validated **strictly**: an unknown section, rule id or key is
an error, not a warning. A typo that silently disables a redaction rule in a CI
gate is worse than a failed build.

Rules can also be toggled per run, which beats the file:

```bash
writeup-scrub scan writeups/ --disable WS006,WS007
writeup-scrub scan writeups/ --enable WS005 --fail-on medium
```

---

## Redaction manifest

`--report FILE` writes a JSON record of every redaction, for an auditable trail
of what left the document:

```json
{
  "tool": "writeup-scrub",
  "version": "0.1.0",
  "generated_at": "2026-10-29T00:00:00+00:00",
  "mode": "clean",
  "plaintext_included": false,
  "summary": {
    "files": 1,
    "files_changed": 1,
    "redactions": 9,
    "warnings": 1,
    "hygiene_changes": 7,
    "by_rule": {
      "MD-HEADING": 4, "MD-LANG": 3,
      "WS001": 2, "WS002": 1, "WS003": 1,
      "WS004": 1, "WS005": 1, "WS006": 3, "WS007": 1
    },
    "by_severity": { "critical": 3, "high": 1, "medium": 2, "low": 3, "info": 8 }
  },
  "files": [
    {
      "path": "Blackfield.md",
      "output_path": "public/Blackfield.md",
      "changed": true,
      "findings": [
        {
          "rule": "WS001",
          "severity": "critical",
          "kind": "redaction",
          "line": 36,
          "message": "platform flag redacted",
          "file": "Blackfield.md",
          "original_fingerprint": "sha256:dd657625ac8050b4",
          "original_preview": "9d1c********",
          "original_length": 32,
          "replacement": "[REDACTED: platform flag]",
          "result_line": "Root flag: [REDACTED: platform flag]"
        }
      ]
    }
  ]
}
```

The manifest records a **fingerprint and a short preview**, not the secret: an
audit trail that is itself a leak is not an improvement. Pass `--report-reveal`
if you want plaintext, and treat that file accordingly. The console output and
the manifest both show the *sanitised* line, so neither prints what was removed.

`diff` is the exception, by design — it shows removed lines in full, because
that is what you are reading it for. Don't paste `diff` output into a PR.

---

## Limitations

Worth being straight about:

- **It is pattern-based.** It catches secrets shaped like secrets it knows. A
  token shaped like nothing in WS002, an internal hostname, a screenshot with
  your desktop in it, a flag written in words — it will miss all of those. A
  human still reads the diff before publishing. This tool exists to catch the
  routine leaks reliably, not to replace that review.
- **Unlabelled 32-hex is a judgement call.** WS001 warns and keeps it. If your
  notes paste flags with no surrounding words at all, set `redact_bare_hex`.
- **WS003's default is broad.** With no `users` list it rewrites every home
  directory, including the target's. Scope it to your own usernames.
- **Inline code spans are not special-cased.** `` `[[like this]]` `` in
  backticks is still converted by WS006. Secrets inside code spans *are*
  redacted, which is the behaviour you want for WS001/WS002.
- **Setext headings** (`Title` over `=====`) are not normalised; ATX headings
  (`# Title`) are.
- **Trailing-whitespace stripping removes markdown hard breaks.** Two trailing
  spaces used as a line break are whitespace to this pass, so they go. If you
  rely on them, set `strip_trailing_whitespace = false`.
- **Phone detection is deliberately narrow** — a parenthesised area code, or a
  3-3-4 grouping with matching separators. It will not match every
  international format, in exchange for never matching an IP address, a port or
  a version string.
- **The retirement check covers Hack The Box only.** Other platforms need an
  adapter, and the interface for writing one is above.
- **Rendered output is not validated.** Hygiene fixes the common breakages; it
  is not a markdown linter.

---

## Tests

```bash
python -m unittest discover -s tests -t . -v
```

286 tests, entirely offline — the retirement check is exercised through a
mocked fetcher, so no test needs network access or a token. Each rule is tested
firing on a positive fixture and staying silent on a negative one, WS001 is
tested in both directions, and every negative fixture is additionally run with
*all* rules enabled to catch one rule's pattern firing on another's fixture.

---

## License

MIT — see [LICENSE](LICENSE).
