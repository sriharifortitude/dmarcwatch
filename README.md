# dmarcwatch

[![CI](https://github.com/sriharifortitude/dmarcwatch/actions/workflows/ci.yml/badge.svg)](https://github.com/sriharifortitude/dmarcwatch/actions/workflows/ci.yml)

Read DMARC aggregate reports and say whether a domain can move to a stricter
policy, and if not, which senders stand in the way. Rust, three small
dependencies (`quick-xml`, `flate2`, `zip`) plus `serde_json`, MIT.

## Why

Publishing `p=none` is easy and protects nothing. Moving to `p=reject` is
what stops someone else sending as your domain, and it is the step people
put off, because getting it wrong means your own invoices, password resets
or newsletters stop arriving. The evidence for whether it is safe is
already in your mailbox: every large receiver sends a daily XML report of
what it saw claiming to be you. Nobody reads them, because each is a few
thousand lines of XML, split by receiver and by day.

dmarcwatch reads a folder of them and answers the question the reports are
for: *if this domain published `p=reject` today, how much mail you want
delivered would be refused, and from where?*

## What it does

Here are three reports for `example.com` (`testdata/blocked/`), from two
receivers over eight days. The domain publishes `p=none`.

<!-- demo-blocked:start -->
```
example.com   p=none sp=- pct=100 adkim=r aspf=r
  2024-05-01 to 2024-05-08 (8.0 days), 3 report(s) from 2 receiver(s)
  messages 1075   pass DMARC 882 (82.0%)   fail 193 (18.0%)
  of the failures: 25 relayed (forwarding, mailing lists), 168 fixable (15.6% of all mail)
  receivers did with the failures: 193 none

  sources that fail DMARC, most fixable first
    192.0.2.20                                   154 of     154 fail   misaligned
      authenticates as bounce.esp-mailer.example.net, esp-mailer.example.net, not as the From domain; set up a custom DKIM domain or Return-Path for it
    198.51.100.7                                  14 of      14 fail   unauthenticated
      passes neither SPF nor DKIM for any domain: add it to SPF/sign with DKIM, or it is not yours
    203.0.113.9                                   25 of      25 fail   relayed
      forwarding or a mailing list, per the receiver; not fixable on your side

  sources that pass only through SPF (forwarding breaks SPF, so this mail can start failing)
    192.0.2.30                                    82 of      82

  NOT READY
    - 15.63% of messages (168 of 1075) fail for a reason that can be fixed; the limit is 0.50%
  next: fix the blockers above, then collect another week of reports
```
<!-- demo-blocked:end -->

Failures are sorted into what you can fix and what you cannot:

- **misaligned**: the sender authenticates, but as someone else. Here an
  email service signs with its own domain and sends from its own bounce
  address, so SPF and DKIM both *pass* and DMARC still fails, because
  neither matches `example.com`. The fix is on the sender's side (a custom
  DKIM domain, a custom return-path) and the report names the domain to look
  for.
- **unauthenticated**: passes neither check for any domain. Either a
  legitimate sender missing from your SPF record, or someone spoofing you.
  The reports cannot tell which; you can, from the address.
- **relayed**: the receiver itself says the failure is down to forwarding or
  a mailing list. Those fail DMARC by design and are not counted against you.

It also lists sources that pass **only through SPF**: they pass today, and
can stop passing the day a recipient forwards the message.

A domain that is clean looks like this (`testdata/ready/`, `p=quarantine`):

<!-- demo-ready:start -->
```
example.org   p=quarantine sp=reject pct=100 adkim=r aspf=r
  2024-05-01 to 2024-05-10 (9.0 days), 2 report(s) from 2 receiver(s)
  messages 1648   pass DMARC 1640 (99.5%)   fail 8 (0.5%)
  of the failures: 8 relayed (forwarding, mailing lists), 0 fixable (0.0% of all mail)
  receivers did with the failures: 8 none

  sources that fail DMARC, most fixable first
    203.0.113.77                                   8 of       8 fail   relayed
      forwarding or a mailing list, per the receiver; not fixable on your side

  READY: the reports show no fixable failures above the limit
  next: move to p=reject
```
<!-- demo-ready:end -->

## Usage

```bash
cargo install --git https://github.com/sriharifortitude/dmarcwatch --tag v0.1.0
dmarcwatch reports/                      # a directory of .xml, .gz and .zip files
dmarcwatch --format json reports/ > summary.json
dmarcwatch --fail-if-not-ready reports/  # exit 1 if any domain is not ready
```

Options: `--max-fail-share PERCENT` (default 0.5), `--min-days N` (default 7),
`--min-messages N` (default 100). Exit codes: 0 ok, 1 a domain is not ready
(only with `--fail-if-not-ready`), 2 usage error or a report that could not be
read. A report that cannot be read is named on stderr and left out of the
figures; the others are still analysed, and the exit code says something was
missing.

Receivers send plain XML, gzip or zip. The format is recognised from the
file's bytes, not its name.

## How the verdict is reached

A domain is **ready** when all three hold:

1. the reports span at least `--min-days` (a monthly invoice run is invisible
   in three days of data);
2. they cover at least `--min-messages`;
3. mail that fails for a fixable reason is at most `--max-fail-share` of all mail.

The 0.5% default is a judgement, not a standard. It is high enough that one
forgotten low-volume sender does not block forever and low enough that a
sender you would miss is usually over it.
[ADR 2](docs/adr/0002-what-ready-means.md) says why, and what the reports
cannot show.

Other things the output does so the figures can be trusted:

- the same receiver sending the same report id twice is counted once;
- the policy shown is from the report that ended last, and a change inside
  the window is flagged;
- mail from subdomains is counted separately, because it follows `sp=`;
- counts are summed with saturation, so a hostile `<count>` cannot panic it.

## Reading untrusted reports

Aggregate reports arrive by email from anyone who knows the `rua` address.
So:

- a DOCTYPE is refused outright, so entity-expansion attacks never start;
- gzip and zip are read through a 64 MiB cap on the decompressed size, and a
  zip may have at most 64 entries. A 64 KiB gzip of zeros is refused, by test;
- a file larger than the cap is refused without being read whole;
- an XML document that ends mid-element is an error, not a smaller report;
- nothing is written to disk, so there is no archive path to escape.

## Tested

```bash
cargo test    # 33 tests
```

Hand-worked figures, one test per failure class, truncated and hostile
inputs, and the CLI's exit codes. Several tests were run against deliberately
broken copies of the code to check they fail (a missing DOCTYPE refusal, a
broken duplicate check, a threshold off by one, a missing size cap).
CI builds on Rust 1.77, the version in `Cargo.toml`, and on stable, and diffs
the two outputs above against a fresh run.

**What this has not been tested against.** The fixtures in `testdata/` were
written by me from the schema in RFC 7489 appendix C. They are *not* captured
from Google, Microsoft or Yahoo, and I have not run dmarcwatch on a real
report. Receivers differ in ways a schema does not show (empty elements,
extension fields, reports for several domains in one file); the parser skips
what it does not recognise and refuses what is malformed, but the first real
report may find something. If one does, that is a bug to file.

## Not covered

- It does not query DNS. It cannot tell you what your SPF record says, only
  what receivers saw.
- Forensic (`ruf`) reports are not read.
- Reports in the newer DMARCbis draft format are read only so far as they
  keep the RFC 7489 element names.
- It cannot tell a legitimate sender you forgot from a spoofer. It says what
  failed; deciding which sources are yours is the part that needs a person.

See [`docs/adr/`](docs/adr/) for the decisions behind it.

## Licence

MIT.
