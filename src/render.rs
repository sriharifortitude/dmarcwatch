//! Terminal and JSON output. Both are deterministic: no clock, no locale.

use crate::aggregate::Alignment;
use crate::analyze::{share, Analysis, Class, DomainSummary, Source};
use serde_json::{json, Value};
use std::fmt::Write;

/// `YYYY-MM-DD` in UTC for a Unix timestamp (Hinnant's civil-from-days).
pub fn date(unix: u64) -> String {
    let z = (unix / 86_400) as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}")
}

fn pct(part: u64, whole: u64) -> String {
    format!("{:.1}%", share(part, whole) * 100.0)
}

fn mode(a: Alignment) -> &'static str {
    match a {
        Alignment::Relaxed => "r",
        Alignment::Strict => "s",
    }
}

fn class_name(c: Class) -> &'static str {
    match c {
        Class::Aligned => "aligned",
        Class::Relayed => "relayed",
        Class::Misaligned => "misaligned",
        Class::Unauthenticated => "unauthenticated",
    }
}

fn explain(s: &Source) -> String {
    match s.class {
        Class::Misaligned => {
            let who: Vec<&str> = s.foreign_domains.iter().map(String::as_str).collect();
            format!("authenticates as {}, not as the From domain; set up a custom DKIM domain or Return-Path for it", who.join(", "))
        }
        Class::Unauthenticated => "passes neither SPF nor DKIM for any domain: add it to SPF/sign with DKIM, or it is not yours".to_string(),
        Class::Relayed => "forwarding or a mailing list, per the receiver; not fixable on your side".to_string(),
        Class::Aligned => String::new(),
    }
}

pub fn terminal(analysis: &Analysis) -> String {
    let mut out = String::new();
    for (i, d) in analysis.domains.iter().enumerate() {
        if i > 0 {
            out.push('\n');
        }
        domain_block(&mut out, d);
    }
    if analysis.duplicates > 0 {
        let _ = writeln!(
            out,
            "\nnote: {} duplicate report(s) ignored (same receiver and report id)",
            analysis.duplicates
        );
    }
    out
}

fn domain_block(out: &mut String, d: &DomainSummary) {
    let p = &d.policy;
    let _ = writeln!(
        out,
        "{}   p={} sp={} pct={} adkim={} aspf={}",
        d.domain,
        p.p,
        p.sp.as_deref().unwrap_or("-"),
        p.pct,
        mode(p.adkim),
        mode(p.aspf)
    );
    let _ = writeln!(
        out,
        "  {} to {} ({:.1} days), {} report(s) from {} receiver(s)",
        date(d.begin),
        date(d.end),
        d.days(),
        d.reports,
        d.receivers.len()
    );
    if d.policy_changed_in_window {
        let _ = writeln!(
            out,
            "  the published policy changed inside this window; figures mix both"
        );
    }
    let _ = writeln!(
        out,
        "  messages {}   pass DMARC {} ({})   fail {} ({})",
        d.messages,
        d.passed,
        pct(d.passed, d.messages),
        d.failed,
        pct(d.failed, d.messages)
    );
    if d.failed > 0 {
        let _ = writeln!(
            out,
            "  of the failures: {} relayed (forwarding, mailing lists), {} fixable ({} of all mail)",
            d.failed_relayed,
            d.fixable_failures(),
            pct(d.fixable_failures(), d.messages)
        );
        let by: Vec<String> = d
            .failed_by_disposition
            .iter()
            .map(|(k, v)| format!("{v} {k}"))
            .collect();
        let _ = writeln!(out, "  receivers did with the failures: {}", by.join(", "));
    }
    if d.subdomain_messages > 0 {
        let _ = writeln!(
            out,
            "  {} message(s) were sent from subdomains; those follow sp=, not p=",
            d.subdomain_messages
        );
    }

    let failing: Vec<&Source> = d.sources.iter().filter(|s| s.failed > 0).collect();
    if !failing.is_empty() {
        let _ = writeln!(out, "\n  sources that fail DMARC, most fixable first");
        for s in failing {
            let _ = writeln!(
                out,
                "    {:<40} {:>7} of {:>7} fail   {}",
                s.ip,
                s.failed,
                s.messages,
                class_name(s.class)
            );
            let note = explain(s);
            if !note.is_empty() {
                let _ = writeln!(out, "      {note}");
            }
        }
    }
    let spf_only: Vec<&Source> = d.sources.iter().filter(|s| s.passed_spf_only > 0).collect();
    if !spf_only.is_empty() {
        let _ = writeln!(out, "\n  sources that pass only through SPF (forwarding breaks SPF, so this mail can start failing)");
        for s in spf_only {
            let _ = writeln!(
                out,
                "    {:<40} {:>7} of {:>7}",
                s.ip, s.passed_spf_only, s.messages
            );
        }
    }

    let v = &d.verdict;
    let _ = writeln!(
        out,
        "\n  {}",
        if v.ready {
            "READY: the reports show no fixable failures above the limit"
        } else {
            "NOT READY"
        }
    );
    for b in &v.blockers {
        let _ = writeln!(out, "    - {b}");
    }
    let _ = writeln!(out, "  next: {}", v.next_step);
}

pub fn json(analysis: &Analysis) -> Value {
    let domains: Vec<Value> = analysis.domains.iter().map(domain_json).collect();
    json!({ "duplicate_reports_ignored": analysis.duplicates, "domains": domains })
}

fn domain_json(d: &DomainSummary) -> Value {
    let sources: Vec<Value> = d
        .sources
        .iter()
        .map(|s| {
            json!({
                "ip": s.ip,
                "class": class_name(s.class),
                "messages": s.messages,
                "passed_both": s.passed_both,
                "passed_dkim_only": s.passed_dkim_only,
                "passed_spf_only": s.passed_spf_only,
                "failed": s.failed,
                "failed_relayed": s.failed_relayed,
                "authenticates_as": s.foreign_domains,
            })
        })
        .collect();
    json!({
        "domain": d.domain,
        "policy": {
            "p": d.policy.p,
            "sp": d.policy.sp,
            "pct": d.policy.pct,
            "adkim": mode(d.policy.adkim),
            "aspf": mode(d.policy.aspf),
        },
        "policy_changed_in_window": d.policy_changed_in_window,
        "begin": date(d.begin),
        "end": date(d.end),
        "days": d.days(),
        "reports": d.reports,
        "receivers": d.receivers,
        "messages": d.messages,
        "passed": d.passed,
        "failed": d.failed,
        "failed_relayed": d.failed_relayed,
        "failed_fixable": d.fixable_failures(),
        "failed_by_disposition": d.failed_by_disposition,
        "subdomain_messages": d.subdomain_messages,
        "sources": sources,
        "verdict": {
            "ready": d.verdict.ready,
            "blockers": d.verdict.blockers,
            "next_step": d.verdict.next_step,
        },
    })
}
