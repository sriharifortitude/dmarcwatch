use dmarcwatch::aggregate::{self, Alignment};
use dmarcwatch::analyze::{analyze, Class, Options};
use dmarcwatch::{input, render};
use std::fmt::Write as _;
use std::io::{Cursor, Write};

const T0: u64 = 1_714_521_600; // 2024-05-01T00:00:00Z
const DAY: u64 = 86_400;

/// One `<record>`; `reason` is the policy_evaluated reason type, if any.
struct Rec {
    ip: &'static str,
    count: u64,
    dkim: bool,
    spf: bool,
    from: &'static str,
    reason: Option<&'static str>,
    dkim_auth: &'static [(&'static str, &'static str)],
    spf_auth: &'static [(&'static str, &'static str)],
}

impl Rec {
    fn pass(ip: &'static str, count: u64) -> Rec {
        Rec {
            ip,
            count,
            dkim: true,
            spf: true,
            from: "example.com",
            reason: None,
            dkim_auth: &[("example.com", "pass")],
            spf_auth: &[("example.com", "pass")],
        }
    }
    fn fail(ip: &'static str, count: u64) -> Rec {
        Rec {
            ip,
            count,
            dkim: false,
            spf: false,
            from: "example.com",
            reason: None,
            dkim_auth: &[],
            spf_auth: &[("example.com", "fail")],
        }
    }
    fn xml(&self) -> String {
        let verdict = |b: bool| if b { "pass" } else { "fail" };
        let reason = self
            .reason
            .map(|r| format!("<reason><type>{r}</type></reason>"))
            .unwrap_or_default();
        let mut auth = String::new();
        for (d, r) in self.dkim_auth {
            write!(
                auth,
                "<dkim><domain>{d}</domain><result>{r}</result></dkim>"
            )
            .unwrap();
        }
        for (d, r) in self.spf_auth {
            write!(auth, "<spf><domain>{d}</domain><result>{r}</result></spf>").unwrap();
        }
        format!(
            "<record><row><source_ip>{}</source_ip><count>{}</count><policy_evaluated><disposition>none</disposition><dkim>{}</dkim><spf>{}</spf>{reason}</policy_evaluated></row>\
             <identifiers><header_from>{}</header_from></identifiers><auth_results>{auth}</auth_results></record>",
            self.ip,
            self.count,
            verdict(self.dkim),
            verdict(self.spf),
            self.from
        )
    }
}

fn report(org: &str, id: &str, begin: u64, end: u64, p: &str, pct: u32, recs: &[Rec]) -> String {
    let body: String = recs.iter().map(Rec::xml).collect();
    format!(
        "<feedback><report_metadata><org_name>{org}</org_name><report_id>{id}</report_id><date_range><begin>{begin}</begin><end>{end}</end></date_range></report_metadata>\
         <policy_published><domain>example.com</domain><p>{p}</p><pct>{pct}</pct></policy_published>{body}</feedback>"
    )
}

fn parse(xml: &str) -> aggregate::Aggregate {
    aggregate::parse(xml.as_bytes()).expect("fixture parses")
}

fn week(recs: &[Rec]) -> aggregate::Aggregate {
    parse(&report(
        "google.com",
        "w1",
        T0,
        T0 + 8 * DAY,
        "none",
        100,
        recs,
    ))
}

// ---- parsing -------------------------------------------------------------

#[test]
fn reads_every_field_of_a_report() {
    let r = parse(
        "<feedback xmlns=\"urn:ietf:params:xml:ns:dmarc-2.0\"><report_metadata><org_name>Example Receiver</org_name><email>x@example.net</email><report_id>42</report_id>\
         <date_range><begin>100</begin><end>200</end></date_range></report_metadata>\
         <policy_published><domain>Example.COM</domain><adkim>s</adkim><aspf>r</aspf><p>Quarantine</p><sp>reject</sp><pct>25</pct></policy_published>\
         <record><row><source_ip>2001:db8::1</source_ip><count>7</count><policy_evaluated><disposition>quarantine</disposition><dkim>fail</dkim><spf>pass</spf>\
         <reason><type>forwarded</type></reason></policy_evaluated></row><identifiers><header_from>Mail.Example.com</header_from></identifiers>\
         <auth_results><dkim><domain>other.net</domain><selector>k1</selector><result>PASS</result></dkim><spf><domain>example.com</domain><scope>mfrom</scope><result>pass</result></spf></auth_results></record></feedback>",
    );
    assert_eq!(
        (r.org.as_str(), r.report_id.as_str(), r.begin, r.end),
        ("Example Receiver", "42", 100, 200)
    );
    assert_eq!(r.domain, "example.com");
    assert_eq!(
        (r.policy.p.as_str(), r.policy.sp.as_deref(), r.policy.pct),
        ("quarantine", Some("reject"), 25)
    );
    assert_eq!(
        (r.policy.adkim, r.policy.aspf),
        (Alignment::Strict, Alignment::Relaxed)
    );
    let rec = &r.records[0];
    assert_eq!(
        (rec.source_ip.as_str(), rec.count, rec.disposition.as_str()),
        ("2001:db8::1", 7, "quarantine")
    );
    assert!(!rec.dkim_aligned && rec.spf_aligned);
    assert_eq!(rec.header_from, "mail.example.com");
    assert_eq!(rec.reasons, vec!["forwarded"]);
    assert_eq!(
        (
            rec.dkim[0].domain.as_str(),
            rec.dkim[0].selector.as_deref(),
            rec.dkim[0].result.as_str()
        ),
        ("other.net", Some("k1"), "pass")
    );
}

#[test]
fn a_truncated_report_is_an_error_not_a_smaller_report() {
    let full = report(
        "a",
        "1",
        0,
        10,
        "none",
        100,
        &[Rec::pass("192.0.2.1", 5), Rec::pass("192.0.2.2", 5)],
    );
    for cut in [full.len() / 3, full.len() / 2, full.len() - 12] {
        let message = aggregate::parse(&full.as_bytes()[..cut]).unwrap_err().0;
        assert!(
            message.contains("report is truncated") || message.contains("not well-formed"),
            "cut at {cut}: {message}"
        );
    }
}

#[test]
fn defaults_follow_rfc_7489() {
    let r = parse(&report("a", "1", 0, 10, "none", 100, &[]).replace("<pct>100</pct>", ""));
    assert_eq!(
        (r.policy.pct, r.policy.adkim, r.policy.aspf),
        (100, Alignment::Relaxed, Alignment::Relaxed)
    );
}

#[test]
fn refuses_a_document_type_declaration() {
    let xml = format!(
        "<!DOCTYPE feedback [<!ENTITY x \"y\">]>{}",
        report("a", "1", 0, 10, "none", 100, &[])
    );
    assert_eq!(
        aggregate::parse(xml.as_bytes()).unwrap_err().0,
        "document type declarations are refused"
    );
}

#[test]
fn an_entity_bomb_is_refused_before_it_expands() {
    let laughs = "<!DOCTYPE lolz [<!ENTITY lol \"lol\"><!ENTITY lol2 \"&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;\">\
                  <!ENTITY lol3 \"&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;\">]><feedback><report_metadata><org_name>&lol3;</org_name></report_metadata></feedback>";
    assert!(aggregate::parse(laughs.as_bytes()).is_err());
}

#[test]
fn unknown_entities_are_errors_not_silently_dropped() {
    let xml = report("a&bogus;", "1", 0, 10, "none", 100, &[]);
    assert!(aggregate::parse(xml.as_bytes())
        .unwrap_err()
        .0
        .contains("bad text or entity"));
}

#[test]
fn rejects_what_is_not_a_report() {
    for (xml, expected) in [
        ("<html><body/></html>", "root element is <html>"),
        ("", "not a DMARC aggregate report"),
        ("<feedback/>", "not a DMARC aggregate report"),
        (
            "<feedback><report_metadata><org_name>a</org_name></report_metadata></feedback>",
            "report has no report_metadata/report_id",
        ),
    ] {
        let message = aggregate::parse(xml.as_bytes()).unwrap_err().0;
        assert!(message.contains(expected), "{xml:?} gave {message:?}");
    }
}

#[test]
fn rejects_malformed_values_with_the_field_named() {
    let good = report("a", "1", 0, 10, "none", 100, &[Rec::pass("192.0.2.1", 1)]);
    for (from, to, expected) in [
        (
            "<count>1</count>",
            "<count>-3</count>",
            "record count \"-3\"",
        ),
        (
            "<count>1</count>",
            "<count>1.5</count>",
            "record count \"1.5\"",
        ),
        ("<p>none</p>", "<p>maybe</p>", "published policy \"maybe\""),
        ("<pct>100</pct>", "<pct>101</pct>", "above 100"),
        (
            "<begin>0</begin>",
            "<begin>99</begin>",
            "ends before it begins",
        ),
        (
            "<source_ip>192.0.2.1</source_ip>",
            "<source_ip></source_ip>",
            "no source_ip",
        ),
    ] {
        let message = aggregate::parse(good.replace(from, to).as_bytes())
            .unwrap_err()
            .0;
        assert!(message.contains(expected), "{to}: {message}");
    }
}

#[test]
fn a_record_without_a_dmarc_verdict_is_an_error() {
    let xml = report("a", "1", 0, 10, "none", 100, &[Rec::pass("192.0.2.1", 1)])
        .replace("<dkim>pass</dkim>", "");
    assert!(aggregate::parse(xml.as_bytes())
        .unwrap_err()
        .0
        .contains("no policy_evaluated/dkim"));
}

#[test]
fn ignores_elements_it_does_not_know() {
    let xml = report("a", "1", 0, 10, "none", 100, &[Rec::pass("192.0.2.1", 3)]).replace(
        "<feedback>",
        "<feedback><extension><vendor>x</vendor></extension>",
    );
    assert_eq!(parse(&xml).records[0].count, 3);
}

// ---- input formats -------------------------------------------------------

fn gzip(data: &[u8]) -> Vec<u8> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(data).unwrap();
    encoder.finish().unwrap()
}

#[test]
fn reads_gzip_and_zip_by_content_not_name() {
    let xml = report("a", "1", 0, 10, "none", 100, &[]);
    assert_eq!(
        input::documents(&gzip(xml.as_bytes())).unwrap()[0].1,
        xml.as_bytes()
    );

    let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
    zip.start_file("report.xml", zip::write::FileOptions::default())
        .unwrap();
    zip.write_all(xml.as_bytes()).unwrap();
    let bytes = zip.finish().unwrap().into_inner();
    let docs = input::documents(&bytes).unwrap();
    assert_eq!(
        (docs[0].0.as_str(), docs[0].1.as_slice()),
        ("report.xml", xml.as_bytes())
    );
}

#[test]
fn a_zip_without_xml_is_an_error() {
    let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
    zip.start_file("notes.txt", zip::write::FileOptions::default())
        .unwrap();
    zip.write_all(b"hello").unwrap();
    let bytes = zip.finish().unwrap().into_inner();
    assert_eq!(
        input::documents(&bytes).unwrap_err(),
        "zip contains no .xml entry"
    );
}

#[test]
fn a_gzip_bomb_is_refused_at_the_cap() {
    // 65 MiB of zeros compresses to about 64 KiB.
    let bomb = gzip(&vec![0u8; (input::MAX_XML_BYTES + 1024 * 1024) as usize]);
    assert!(bomb.len() < 200_000, "fixture is not small: {}", bomb.len());
    let message = input::documents(&bomb).unwrap_err();
    assert!(message.contains("expands beyond 64 MiB"), "{message}");
}

#[test]
fn a_truncated_gzip_is_an_error_not_a_short_report() {
    let full = gzip(report("a", "1", 0, 10, "none", 100, &[Rec::pass("192.0.2.1", 1)]).as_bytes());
    assert!(input::documents(&full[..full.len() / 2]).is_err());
}

// ---- analysis ------------------------------------------------------------

#[test]
fn counts_add_up_and_sources_are_classified() {
    let esp = Rec {
        dkim_auth: &[("esp.example.net", "pass")],
        spf_auth: &[("bounce.esp.example.net", "pass")],
        ..Rec::fail("192.0.2.20", 60)
    };
    let fwd = Rec {
        reason: Some("forwarded"),
        ..Rec::fail("203.0.113.9", 10)
    };
    let spf_only = Rec {
        dkim: false,
        dkim_auth: &[],
        ..Rec::pass("192.0.2.30", 40)
    };
    let a = analyze(
        vec![week(&[
            Rec::pass("192.0.2.10", 300),
            esp,
            Rec::fail("198.51.100.7", 5),
            fwd,
            spf_only,
        ])],
        Options::default(),
    );
    let d = &a.domains[0];
    assert_eq!(
        (d.messages, d.passed, d.failed, d.failed_relayed),
        (415, 340, 75, 10)
    );
    assert_eq!(d.fixable_failures(), 65);

    let class = |ip: &str| d.sources.iter().find(|s| s.ip == ip).unwrap().class;
    assert_eq!(class("192.0.2.10"), Class::Aligned);
    assert_eq!(class("192.0.2.20"), Class::Misaligned);
    assert_eq!(class("198.51.100.7"), Class::Unauthenticated);
    assert_eq!(class("203.0.113.9"), Class::Relayed);
    assert_eq!(
        d.sources[0].ip, "192.0.2.20",
        "the most fixable source comes first"
    );
    let spf = d.sources.iter().find(|s| s.ip == "192.0.2.30").unwrap();
    assert_eq!((spf.passed_spf_only, spf.failed), (40, 0));
    let misaligned = d.sources.iter().find(|s| s.ip == "192.0.2.20").unwrap();
    assert_eq!(
        misaligned
            .foreign_domains
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        ["bounce.esp.example.net", "esp.example.net"]
    );
}

#[test]
fn the_same_receiver_and_report_id_counts_once() {
    let one = week(&[Rec::pass("192.0.2.10", 500)]);
    let a = analyze(vec![one.clone(), one.clone()], Options::default());
    assert_eq!(
        (a.duplicates, a.domains[0].messages, a.domains[0].reports),
        (1, 500, 1)
    );

    // Another receiver reusing the id is a different report.
    let other = aggregate::Aggregate {
        org: "outlook.com".into(),
        ..one.clone()
    };
    assert_eq!(
        analyze(vec![one, other], Options::default()).domains[0].messages,
        1000
    );
}

#[test]
fn a_ready_domain_needs_enough_days_enough_mail_and_few_fixable_failures() {
    let healthy = [Rec::pass("192.0.2.10", 1000)];
    assert!(
        analyze(vec![week(&healthy)], Options::default()).domains[0]
            .verdict
            .ready
    );

    let short = parse(&report("g", "1", T0, T0 + 2 * DAY, "none", 100, &healthy));
    let v = &analyze(vec![short], Options::default()).domains[0].verdict;
    assert!(!v.ready && v.blockers[0].contains("span 2.0 days"), "{v:?}");

    let thin = week(&[Rec::pass("192.0.2.10", 99)]);
    assert!(analyze(vec![thin], Options::default()).domains[0]
        .verdict
        .blockers[0]
        .contains("99 messages"));

    // 5 fixable failures in 1000 is exactly 0.5%: at the limit, so still ready; 6 is not.
    let at_limit = week(&[Rec::pass("192.0.2.10", 995), Rec::fail("198.51.100.7", 5)]);
    assert!(
        analyze(vec![at_limit], Options::default()).domains[0]
            .verdict
            .ready
    );
    let over = week(&[Rec::pass("192.0.2.10", 994), Rec::fail("198.51.100.7", 6)]);
    assert!(
        !analyze(vec![over], Options::default()).domains[0]
            .verdict
            .ready
    );
}

#[test]
fn relayed_failures_never_block() {
    let fwd = Rec {
        reason: Some("mailing_list"),
        ..Rec::fail("203.0.113.9", 400)
    };
    let a = analyze(
        vec![week(&[Rec::pass("192.0.2.10", 600), fwd])],
        Options::default(),
    );
    assert!(a.domains[0].verdict.ready);
}

#[test]
fn the_next_step_follows_the_published_policy() {
    let step = |p: &str, pct: u32| {
        let r = parse(&report(
            "g",
            "1",
            T0,
            T0 + 8 * DAY,
            p,
            pct,
            &[Rec::pass("192.0.2.10", 500)],
        ));
        analyze(vec![r], Options::default()).domains[0]
            .verdict
            .next_step
            .clone()
    };
    assert_eq!(step("none", 100), "move to p=quarantine");
    assert_eq!(step("quarantine", 100), "move to p=reject");
    assert_eq!(
        step("quarantine", 10),
        "raise pct from 10 to 100, then move to p=reject"
    );
    assert_eq!(
        step("reject", 100),
        "nothing: the domain already publishes p=reject at pct=100"
    );
    assert_eq!(step("reject", 50), "raise pct from 50 to 100");
}

#[test]
fn the_policy_comes_from_the_latest_report_and_a_change_is_flagged() {
    let old = parse(&report(
        "g",
        "1",
        T0,
        T0 + 4 * DAY,
        "none",
        100,
        &[Rec::pass("192.0.2.10", 500)],
    ));
    let new = parse(&report(
        "g",
        "2",
        T0 + 4 * DAY,
        T0 + 8 * DAY,
        "quarantine",
        100,
        &[Rec::pass("192.0.2.10", 500)],
    ));
    for order in [vec![old.clone(), new.clone()], vec![new, old]] {
        let d = &analyze(order, Options::default()).domains[0].clone();
        assert_eq!(d.policy.p, "quarantine");
        assert!(d.policy_changed_in_window);
    }
}

#[test]
fn subdomain_mail_is_counted_separately() {
    let sub = Rec {
        from: "news.example.com",
        ..Rec::pass("192.0.2.10", 40)
    };
    let lookalike = Rec {
        from: "badexample.com",
        ..Rec::pass("192.0.2.11", 7)
    };
    let d = &analyze(
        vec![week(&[Rec::pass("192.0.2.10", 60), sub, lookalike])],
        Options::default(),
    )
    .domains[0]
        .clone();
    assert_eq!(d.subdomain_messages, 40);
}

#[test]
fn huge_counts_saturate_instead_of_panicking() {
    let d = &analyze(
        vec![week(&[
            Rec::pass("192.0.2.10", u64::MAX),
            Rec::pass("192.0.2.11", u64::MAX),
            Rec::fail("192.0.2.12", u64::MAX),
        ])],
        Options::default(),
    )
    .domains[0]
        .clone();
    assert_eq!(d.messages, u64::MAX);
    let _ = render::terminal(&analyze(
        vec![week(&[Rec::pass("192.0.2.10", u64::MAX)])],
        Options::default(),
    ));
}

#[test]
fn separate_domains_are_summarised_separately() {
    let other = report(
        "g",
        "9",
        T0,
        T0 + 8 * DAY,
        "none",
        100,
        &[Rec::pass("192.0.2.10", 500)],
    )
    .replace(
        "<domain>example.com</domain>",
        "<domain>example.org</domain>",
    );
    let a = analyze(
        vec![week(&[Rec::pass("192.0.2.10", 500)]), parse(&other)],
        Options::default(),
    );
    assert_eq!(
        a.domains
            .iter()
            .map(|d| d.domain.as_str())
            .collect::<Vec<_>>(),
        ["example.com", "example.org"]
    );
}

// ---- rendering -----------------------------------------------------------

#[test]
fn dates_are_right_across_leap_days_and_centuries() {
    for (unix, expected) in [
        (0, "1970-01-01"),
        (951_782_400, "2000-02-29"),
        (951_868_800, "2000-03-01"),
        (1_709_164_800, "2024-02-29"),
        (1_714_521_600, "2024-05-01"),
        (4_102_444_799, "2099-12-31"),
        (4_102_444_800, "2100-01-01"),
        (4_107_542_400, "2100-03-01"),
    ] {
        assert_eq!(render::date(unix), expected, "{unix}");
    }
}
