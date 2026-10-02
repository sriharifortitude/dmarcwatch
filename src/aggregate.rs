//! Parsing of DMARC aggregate reports (RFC 7489, appendix C).
//!
//! The reader is deliberately strict about what it refuses and lenient about
//! what it ignores. A document type declaration is refused outright: aggregate
//! reports never need one, and entity expansion is the classic way to turn a
//! report parser into a memory bomb. Unknown elements are skipped, because
//! receivers add their own extensions.

use quick_xml::events::{BytesStart, Event};
use quick_xml::Reader;
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Alignment {
    Relaxed,
    Strict,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    /// `none`, `quarantine` or `reject`.
    pub p: String,
    pub sp: Option<String>,
    pub pct: u8,
    pub adkim: Alignment,
    pub aspf: Alignment,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthResult {
    pub domain: String,
    pub selector: Option<String>,
    pub result: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub source_ip: String,
    pub count: u64,
    /// What the receiver did with the message: none, quarantine or reject.
    pub disposition: String,
    /// DMARC's own verdict on DKIM: a pass here means a *aligned* pass.
    pub dkim_aligned: bool,
    pub spf_aligned: bool,
    pub header_from: String,
    /// `policy_evaluated/reason/type`: forwarded, mailing_list, local_policy...
    pub reasons: Vec<String>,
    pub dkim: Vec<AuthResult>,
    pub spf: Vec<AuthResult>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Aggregate {
    pub org: String,
    pub report_id: String,
    /// Unix seconds.
    pub begin: u64,
    pub end: u64,
    pub domain: String,
    pub policy: Policy,
    pub records: Vec<Record>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct ParseError(pub String);

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

fn err<T>(message: impl Into<String>) -> Result<T, ParseError> {
    Err(ParseError(message.into()))
}

#[derive(Default)]
struct Draft {
    org: Option<String>,
    report_id: Option<String>,
    begin: Option<u64>,
    end: Option<u64>,
    domain: Option<String>,
    p: Option<String>,
    sp: Option<String>,
    pct: Option<u8>,
    adkim: Option<Alignment>,
    aspf: Option<Alignment>,
}

#[derive(Default)]
struct RecordDraft {
    source_ip: Option<String>,
    count: Option<u64>,
    disposition: Option<String>,
    dkim_aligned: Option<bool>,
    spf_aligned: Option<bool>,
    header_from: Option<String>,
    reasons: Vec<String>,
    dkim: Vec<AuthDraft>,
    spf: Vec<AuthDraft>,
}

#[derive(Default)]
struct AuthDraft {
    domain: Option<String>,
    selector: Option<String>,
    result: Option<String>,
}

impl AuthDraft {
    fn finish(self, what: &str) -> Result<AuthResult, ParseError> {
        Ok(AuthResult {
            domain: self.domain.unwrap_or_default(),
            selector: self.selector.filter(|s| !s.is_empty()),
            result: match self.result {
                Some(r) => r.to_ascii_lowercase(),
                None => return err(format!("{what} auth result has no <result>")),
            },
        })
    }
}

fn alignment(text: &str) -> Result<Alignment, ParseError> {
    match text.to_ascii_lowercase().as_str() {
        "r" => Ok(Alignment::Relaxed),
        "s" => Ok(Alignment::Strict),
        other => err(format!(
            "alignment mode {other:?} is neither \"r\" nor \"s\""
        )),
    }
}

fn number<T: std::str::FromStr>(text: &str, what: &str) -> Result<T, ParseError> {
    text.parse()
        .or_else(|_| err(format!("{what} {text:?} is not a non-negative integer")))
}

pub fn parse(xml: &[u8]) -> Result<Aggregate, ParseError> {
    let mut reader = Reader::from_reader(xml);
    reader.trim_text(true);

    let mut path: Vec<String> = Vec::new();
    let mut draft = Draft::default();
    let mut records: Vec<Record> = Vec::new();
    let mut current: Option<RecordDraft> = None;
    let mut buf = Vec::new();

    loop {
        let event = reader.read_event_into(&mut buf).map_err(|e| {
            ParseError(format!(
                "not well-formed XML at byte {}: {e}",
                reader.buffer_position()
            ))
        })?;
        match event {
            Event::DocType(_) => return err("document type declarations are refused"),
            Event::Start(e) => {
                open(&mut path, &e, &mut current)?;
            }
            Event::Empty(e) => {
                open(&mut path, &e, &mut current)?;
                leave(&path, &mut current, &mut records)?;
                path.pop();
            }
            Event::End(_) => {
                leave(&path, &mut current, &mut records)?;
                path.pop();
            }
            Event::Text(t) => {
                let text = t
                    .unescape()
                    .map_err(|e| ParseError(format!("bad text or entity: {e}")))?
                    .into_owned();
                assign(&path, &text, &mut draft, &mut current)?;
            }
            Event::Eof => {
                if let Some(open) = path.last() {
                    return err(format!(
                        "document ends inside <{open}>: the report is truncated"
                    ));
                }
                break;
            }
            _ => {}
        }
        buf.clear();
    }

    if draft.domain.is_none() && draft.org.is_none() {
        return err("no <feedback> content: this is not a DMARC aggregate report");
    }
    let need = |value: Option<String>, what: &str| {
        value
            .filter(|v| !v.is_empty())
            .ok_or_else(|| ParseError(format!("report has no {what}")))
    };
    let org = need(draft.org, "report_metadata/org_name")?;
    let report_id = need(draft.report_id, "report_metadata/report_id")?;
    let domain = need(draft.domain, "policy_published/domain")?.to_ascii_lowercase();
    let p = need(draft.p, "policy_published/p")?.to_ascii_lowercase();
    if !matches!(p.as_str(), "none" | "quarantine" | "reject") {
        return err(format!(
            "published policy {p:?} is not none, quarantine or reject"
        ));
    }
    let (begin, end) = match (draft.begin, draft.end) {
        (Some(b), Some(e)) if b <= e => (b, e),
        (Some(_), Some(_)) => return err("date_range ends before it begins"),
        _ => return err("report has no date_range"),
    };
    Ok(Aggregate {
        org,
        report_id,
        begin,
        end,
        domain,
        policy: Policy {
            p,
            sp: draft.sp.map(|s| s.to_ascii_lowercase()),
            pct: draft.pct.unwrap_or(100),
            adkim: draft.adkim.unwrap_or(Alignment::Relaxed),
            aspf: draft.aspf.unwrap_or(Alignment::Relaxed),
        },
        records,
    })
}

fn open(
    path: &mut Vec<String>,
    e: &BytesStart<'_>,
    current: &mut Option<RecordDraft>,
) -> Result<(), ParseError> {
    let name = String::from_utf8_lossy(e.local_name().as_ref()).into_owned();
    if path.is_empty() && name != "feedback" {
        return err(format!("root element is <{name}>, not <feedback>"));
    }
    path.push(name);
    enter(path, current);
    Ok(())
}

fn is(path: &[String], tail: &[&str]) -> bool {
    path.len() == tail.len() + 1 && path[1..].iter().zip(tail).all(|(a, b)| a == b)
}

fn enter(path: &[String], current: &mut Option<RecordDraft>) {
    if is(path, &["record"]) {
        *current = Some(RecordDraft::default());
    } else if let Some(rec) = current {
        if is(path, &["record", "auth_results", "dkim"]) {
            rec.dkim.push(AuthDraft::default());
        } else if is(path, &["record", "auth_results", "spf"]) {
            rec.spf.push(AuthDraft::default());
        }
    }
}

fn leave(
    path: &[String],
    current: &mut Option<RecordDraft>,
    records: &mut Vec<Record>,
) -> Result<(), ParseError> {
    if !is(path, &["record"]) {
        return Ok(());
    }
    let Some(rec) = current.take() else {
        return Ok(());
    };
    let source_ip = rec
        .source_ip
        .filter(|s| !s.is_empty())
        .ok_or_else(|| ParseError("record has no source_ip".into()))?;
    let count = rec
        .count
        .ok_or_else(|| ParseError(format!("record from {source_ip} has no count")))?;
    let verdict = |v: Option<bool>, what: &str| {
        v.ok_or_else(|| {
            ParseError(format!(
                "record from {source_ip} has no policy_evaluated/{what}"
            ))
        })
    };
    records.push(Record {
        dkim_aligned: verdict(rec.dkim_aligned, "dkim")?,
        spf_aligned: verdict(rec.spf_aligned, "spf")?,
        disposition: rec.disposition.unwrap_or_else(|| "none".into()),
        header_from: rec.header_from.unwrap_or_default().to_ascii_lowercase(),
        reasons: rec.reasons,
        dkim: rec
            .dkim
            .into_iter()
            .map(|a| a.finish("DKIM"))
            .collect::<Result<_, _>>()?,
        spf: rec
            .spf
            .into_iter()
            .map(|a| a.finish("SPF"))
            .collect::<Result<_, _>>()?,
        source_ip,
        count,
    });
    Ok(())
}

fn assign(
    path: &[String],
    text: &str,
    d: &mut Draft,
    current: &mut Option<RecordDraft>,
) -> Result<(), ParseError> {
    let text = text.trim();
    if is(path, &["report_metadata", "org_name"]) {
        d.org = Some(text.to_string());
    } else if is(path, &["report_metadata", "report_id"]) {
        d.report_id = Some(text.to_string());
    } else if is(path, &["report_metadata", "date_range", "begin"]) {
        d.begin = Some(number(text, "date_range/begin")?);
    } else if is(path, &["report_metadata", "date_range", "end"]) {
        d.end = Some(number(text, "date_range/end")?);
    } else if is(path, &["policy_published", "domain"]) {
        d.domain = Some(text.to_string());
    } else if is(path, &["policy_published", "p"]) {
        d.p = Some(text.to_string());
    } else if is(path, &["policy_published", "sp"]) {
        d.sp = Some(text.to_string());
    } else if is(path, &["policy_published", "pct"]) {
        let pct: u8 = number(text, "policy_published/pct")?;
        if pct > 100 {
            return err(format!("policy_published/pct is {pct}, above 100"));
        }
        d.pct = Some(pct);
    } else if is(path, &["policy_published", "adkim"]) {
        d.adkim = Some(alignment(text)?);
    } else if is(path, &["policy_published", "aspf"]) {
        d.aspf = Some(alignment(text)?);
    } else if let Some(rec) = current {
        if is(path, &["record", "row", "source_ip"]) {
            rec.source_ip = Some(text.to_string());
        } else if is(path, &["record", "row", "count"]) {
            rec.count = Some(number(text, "record count")?);
        } else if is(path, &["record", "row", "policy_evaluated", "disposition"]) {
            rec.disposition = Some(text.to_ascii_lowercase());
        } else if is(path, &["record", "row", "policy_evaluated", "dkim"]) {
            rec.dkim_aligned = Some(text.eq_ignore_ascii_case("pass"));
        } else if is(path, &["record", "row", "policy_evaluated", "spf"]) {
            rec.spf_aligned = Some(text.eq_ignore_ascii_case("pass"));
        } else if is(
            path,
            &["record", "row", "policy_evaluated", "reason", "type"],
        ) {
            rec.reasons.push(text.to_ascii_lowercase());
        } else if is(path, &["record", "identifiers", "header_from"]) {
            rec.header_from = Some(text.to_string());
        } else if let Some(auth) = auth_target(path, rec) {
            match path.last().map(String::as_str) {
                Some("domain") => auth.domain = Some(text.to_string()),
                Some("selector") => auth.selector = Some(text.to_string()),
                Some("result") => auth.result = Some(text.to_string()),
                _ => {}
            }
        }
    }
    Ok(())
}

/// The DKIM or SPF result being filled in, if `path` is a field of one.
fn auth_target<'a>(path: &[String], rec: &'a mut RecordDraft) -> Option<&'a mut AuthDraft> {
    if path.len() == 5 && path[1] == "record" && path[2] == "auth_results" {
        match path[3].as_str() {
            "dkim" => return rec.dkim.last_mut(),
            "spf" => return rec.spf.last_mut(),
            _ => {}
        }
    }
    None
}
