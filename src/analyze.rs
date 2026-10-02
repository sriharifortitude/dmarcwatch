//! From parsed reports to a per-domain verdict.
//!
//! The question being answered: if this domain published `p=reject` today,
//! how much mail that its owner would want delivered would be refused?
//! Aggregate reports cannot say which mail is wanted, only which mail fails
//! DMARC. So the analysis separates failures an administrator can fix (a
//! sender that authenticates, but as someone else's domain; one that does not
//! authenticate at all) from those inherent to how mail is relayed
//! (forwarding and mailing lists, which the receiver itself labels), and the
//! verdict is about the first group only.

use crate::aggregate::{Aggregate, Policy};
use std::collections::{BTreeMap, BTreeSet, HashSet};

#[derive(Debug, Clone, Copy)]
pub struct Options {
    /// Largest share of messages, 0.0 to 1.0, that may fail for a reason the
    /// owner can fix before the domain is called ready.
    pub max_fail_share: f64,
    /// Fewest days the reports must span.
    pub min_days: f64,
    /// Fewest messages the reports must cover.
    pub min_messages: u64,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            max_fail_share: 0.005,
            min_days: 7.0,
            min_messages: 100,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Class {
    /// Every message passed DMARC.
    Aligned,
    /// Failing mail is explained by forwarding or a mailing list, per the receiver.
    Relayed,
    /// Fails DMARC but authenticates as a different domain (a third-party sender).
    Misaligned,
    /// Fails DMARC and passes neither SPF nor DKIM for any domain.
    Unauthenticated,
}

#[derive(Debug, Clone)]
pub struct Source {
    pub ip: String,
    pub messages: u64,
    pub passed_both: u64,
    pub passed_dkim_only: u64,
    pub passed_spf_only: u64,
    pub failed: u64,
    /// Failed, and the receiver says forwarding or a mailing list caused it.
    pub failed_relayed: u64,
    /// Domains this source authenticated as, on messages that failed alignment.
    pub foreign_domains: BTreeSet<String>,
    pub class: Class,
}

impl Source {
    pub fn fixable_failures(&self) -> u64 {
        self.failed - self.failed_relayed
    }
}

#[derive(Debug, Clone)]
pub struct Verdict {
    pub ready: bool,
    pub blockers: Vec<String>,
    pub next_step: String,
}

#[derive(Debug, Clone)]
pub struct DomainSummary {
    pub domain: String,
    /// Taken from the report that ended last.
    pub policy: Policy,
    pub policy_changed_in_window: bool,
    pub reports: usize,
    pub receivers: BTreeSet<String>,
    pub begin: u64,
    pub end: u64,
    pub messages: u64,
    pub passed: u64,
    pub failed: u64,
    pub failed_relayed: u64,
    /// Failing messages by what the receiver did: none, quarantine, reject.
    pub failed_by_disposition: BTreeMap<String, u64>,
    /// Messages whose From domain is a subdomain of the policy domain.
    pub subdomain_messages: u64,
    pub sources: Vec<Source>,
    pub verdict: Verdict,
}

impl DomainSummary {
    pub fn days(&self) -> f64 {
        (self.end - self.begin) as f64 / 86_400.0
    }
    pub fn fixable_failures(&self) -> u64 {
        self.failed - self.failed_relayed
    }
    pub fn fixable_share(&self) -> f64 {
        share(self.fixable_failures(), self.messages)
    }
}

pub fn share(part: u64, whole: u64) -> f64 {
    if whole == 0 {
        0.0
    } else {
        part as f64 / whole as f64
    }
}

#[derive(Debug)]
pub struct Analysis {
    pub domains: Vec<DomainSummary>,
    /// Reports dropped because the same receiver sent the same report id twice.
    pub duplicates: usize,
}

pub fn analyze(reports: Vec<Aggregate>, options: Options) -> Analysis {
    // Receivers resend reports, and an administrator who points two mailboxes
    // at one rua address gets each twice. Counting both would double every
    // figure, so a report id is counted once per receiver.
    let mut seen = HashSet::new();
    let mut unique = Vec::new();
    let mut duplicates = 0;
    for report in reports {
        if seen.insert((report.org.clone(), report.report_id.clone())) {
            unique.push(report);
        } else {
            duplicates += 1;
        }
    }

    let mut by_domain: BTreeMap<String, Vec<Aggregate>> = BTreeMap::new();
    for report in unique {
        by_domain
            .entry(report.domain.clone())
            .or_default()
            .push(report);
    }
    let domains = by_domain
        .into_iter()
        .map(|(domain, reports)| summarise(domain, reports, options))
        .collect();
    Analysis {
        domains,
        duplicates,
    }
}

#[derive(Default)]
struct Tally {
    messages: u64,
    both: u64,
    dkim_only: u64,
    spf_only: u64,
    failed: u64,
    relayed: u64,
    failed_with_foreign_pass: u64,
    foreign: BTreeSet<String>,
}

fn summarise(domain: String, reports: Vec<Aggregate>, options: Options) -> DomainSummary {
    let latest = reports
        .iter()
        .max_by_key(|r| (r.end, r.begin))
        .expect("grouped reports are never empty");
    let policy = latest.policy.clone();
    let policy_changed_in_window = reports.iter().any(|r| r.policy != policy);
    let begin = reports.iter().map(|r| r.begin).min().unwrap_or(0);
    let end = reports.iter().map(|r| r.end).max().unwrap_or(0);
    let receivers = reports.iter().map(|r| r.org.clone()).collect();
    let report_count = reports.len();

    let mut tallies: BTreeMap<String, Tally> = BTreeMap::new();
    let mut failed_by_disposition: BTreeMap<String, u64> = BTreeMap::new();
    let mut subdomain_messages = 0u64;
    for record in reports.iter().flat_map(|r| &r.records) {
        let t = tallies.entry(record.source_ip.clone()).or_default();
        t.messages = t.messages.saturating_add(record.count);
        if record.header_from.ends_with(&format!(".{domain}")) {
            subdomain_messages = subdomain_messages.saturating_add(record.count);
        }
        match (record.dkim_aligned, record.spf_aligned) {
            (true, true) => t.both = t.both.saturating_add(record.count),
            (true, false) => t.dkim_only = t.dkim_only.saturating_add(record.count),
            (false, true) => t.spf_only = t.spf_only.saturating_add(record.count),
            (false, false) => {
                t.failed = t.failed.saturating_add(record.count);
                let by = failed_by_disposition
                    .entry(record.disposition.clone())
                    .or_default();
                *by = by.saturating_add(record.count);
                if record
                    .reasons
                    .iter()
                    .any(|r| r == "forwarded" || r == "mailing_list")
                {
                    t.relayed = t.relayed.saturating_add(record.count);
                } else {
                    // The mail failed alignment. Did anything authenticate, just not as us?
                    let passed: Vec<&str> = record
                        .dkim
                        .iter()
                        .chain(&record.spf)
                        .filter(|a| a.result == "pass")
                        .map(|a| a.domain.as_str())
                        .collect();
                    if !passed.is_empty() {
                        t.failed_with_foreign_pass =
                            t.failed_with_foreign_pass.saturating_add(record.count);
                        t.foreign.extend(
                            passed
                                .into_iter()
                                .filter(|d| !d.is_empty())
                                .map(str::to_ascii_lowercase),
                        );
                    }
                }
            }
        }
    }

    let mut sources: Vec<Source> = tallies
        .into_iter()
        .map(|(ip, t)| {
            let fixable = t.failed - t.relayed;
            let class = if t.failed == 0 {
                Class::Aligned
            } else if fixable == 0 {
                Class::Relayed
            } else if t.failed_with_foreign_pass * 2 >= fixable {
                Class::Misaligned
            } else {
                Class::Unauthenticated
            };
            Source {
                ip,
                messages: t.messages,
                passed_both: t.both,
                passed_dkim_only: t.dkim_only,
                passed_spf_only: t.spf_only,
                failed: t.failed,
                failed_relayed: t.relayed,
                foreign_domains: t.foreign,
                class,
            }
        })
        .collect();
    // Most fixable failures first, then busiest, then by address for a stable order.
    sources.sort_by(|a, b| {
        b.fixable_failures()
            .cmp(&a.fixable_failures())
            .then(b.messages.cmp(&a.messages))
            .then(a.ip.cmp(&b.ip))
    });

    let messages = sources
        .iter()
        .fold(0u64, |n, s| n.saturating_add(s.messages));
    let failed = sources.iter().fold(0u64, |n, s| n.saturating_add(s.failed));
    let failed_relayed = sources
        .iter()
        .fold(0u64, |n, s| n.saturating_add(s.failed_relayed));
    let mut summary = DomainSummary {
        domain,
        policy,
        policy_changed_in_window,
        reports: report_count,
        receivers,
        begin,
        end,
        messages,
        passed: messages.saturating_sub(failed),
        failed,
        failed_relayed,
        failed_by_disposition,
        subdomain_messages,
        sources,
        verdict: Verdict {
            ready: false,
            blockers: Vec::new(),
            next_step: String::new(),
        },
    };
    summary.verdict = judge(&summary, options);
    summary
}

fn judge(s: &DomainSummary, options: Options) -> Verdict {
    let mut blockers = Vec::new();
    if s.days() < options.min_days {
        blockers.push(format!(
            "the reports span {:.1} days; at least {} are needed to see weekly and monthly senders",
            s.days(),
            options.min_days
        ));
    }
    if s.messages < options.min_messages {
        blockers.push(format!(
            "the reports cover {} messages; at least {} are needed",
            s.messages, options.min_messages
        ));
    }
    if s.fixable_share() > options.max_fail_share {
        blockers.push(format!(
            "{:.2}% of messages ({} of {}) fail for a reason that can be fixed; the limit is {:.2}%",
            s.fixable_share() * 100.0,
            s.fixable_failures(),
            s.messages,
            options.max_fail_share * 100.0
        ));
    }
    let ready = blockers.is_empty();
    let next_step = if !ready {
        "fix the blockers above, then collect another week of reports".to_string()
    } else {
        match (s.policy.p.as_str(), s.policy.pct) {
            ("none", _) => "move to p=quarantine".to_string(),
            ("quarantine", 100) => "move to p=reject".to_string(),
            ("quarantine", pct) => format!("raise pct from {pct} to 100, then move to p=reject"),
            (_, 100) => "nothing: the domain already publishes p=reject at pct=100".to_string(),
            (_, pct) => format!("raise pct from {pct} to 100"),
        }
    };
    Verdict {
        ready,
        blockers,
        next_step,
    }
}
