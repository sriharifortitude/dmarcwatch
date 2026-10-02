# 0001. Failures are sorted by whether the domain owner can fix them

**Status:** accepted

## Decision

A message that fails DMARC is put in one of three groups, and only the
first two count against a domain:

- **misaligned**: SPF or DKIM passed, but for a domain other than the From
  domain.
- **unauthenticated**: neither passed for any domain.
- **relayed**: the receiver's `policy_evaluated/reason/type` is `forwarded`
  or `mailing_list`.

A source is *misaligned* if at least half its fixable failing messages
authenticated as another domain, otherwise *unauthenticated*.

## Reasoning

A single failure rate is what most tools print, and it is the wrong number.
Forwarding and mailing lists break DMARC for mail that was sent correctly,
and no change to the sender's DNS fixes that. A domain with 3% failures, all
forwarded, is ready for `p=reject`. A domain with 1% failures that are all
its payment provider is not. The two look different only once the failures
are separated by cause.

The misaligned/unauthenticated split exists because the two have different
fixes and different readings. Misaligned mail comes from a real sender that
is almost certainly yours. Unauthenticated mail might be a forgotten server
or a spoofer.

## Costs

The *relayed* group depends on the receiver labelling the override, and not
every receiver does. Forwarded mail that arrives unlabelled is counted as
fixable, which makes the verdict stricter than it should be, never looser.
The 50% rule for misaligned versus unauthenticated is a threshold of
convenience for display; it does not affect the verdict.
