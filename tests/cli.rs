use std::path::PathBuf;
use std::process::{Command, Output};

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_dmarcwatch"))
}

fn testdata(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("testdata")
        .join(rel)
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).replace("\r\n", "\n")
}

fn run(args: &[&str]) -> Output {
    bin().args(args).output().expect("binary runs")
}

#[test]
fn a_domain_with_fixable_failures_is_not_ready() {
    let out = run(&[testdata("blocked").to_str().unwrap()]);
    let stdout = text(&out.stdout);
    assert_eq!(
        out.status.code(),
        Some(0),
        "without --fail-if-not-ready the verdict is output, not an exit code"
    );
    assert!(stdout.contains("NOT READY"), "{stdout}");
    assert!(
        stdout.contains("messages 1075   pass DMARC 882 (82.0%)   fail 193 (18.0%)"),
        "{stdout}"
    );
    assert!(
        stdout.contains("192.0.2.20")
            && stdout
                .contains("authenticates as bounce.esp-mailer.example.net, esp-mailer.example.net"),
        "{stdout}"
    );
}

#[test]
fn fail_if_not_ready_sets_the_exit_code() {
    let dir = testdata("blocked");
    assert_eq!(
        run(&["--fail-if-not-ready", dir.to_str().unwrap()])
            .status
            .code(),
        Some(1)
    );
    let ready = testdata("ready");
    assert_eq!(
        run(&["--fail-if-not-ready", ready.to_str().unwrap()])
            .status
            .code(),
        Some(0)
    );
}

#[test]
fn a_clean_domain_is_ready_and_told_the_next_step() {
    let out = run(&[testdata("ready").to_str().unwrap()]);
    let stdout = text(&out.stdout);
    assert!(
        stdout.contains("READY") && stdout.contains("next: move to p=reject"),
        "{stdout}"
    );
}

#[test]
fn the_thresholds_are_adjustable() {
    let dir = testdata("blocked");
    let loose = run(&[
        "--max-fail-share",
        "20",
        "--fail-if-not-ready",
        dir.to_str().unwrap(),
    ]);
    assert_eq!(loose.status.code(), Some(0), "{}", text(&loose.stdout));
    let long = run(&["--min-days=30", dir.to_str().unwrap()]);
    assert!(text(&long.stdout).contains("the reports span 8.0 days; at least 30"));
}

#[test]
fn json_output_is_stable_and_complete() {
    let out = run(&["--format", "json", testdata("ready").to_str().unwrap()]);
    let stdout = text(&out.stdout);
    for expected in [
        "\"domain\": \"example.org\"",
        "\"messages\": 1648",
        "\"failed_relayed\": 8",
        "\"failed_fixable\": 0",
        "\"begin\": \"2024-05-01\"",
        "\"ready\": true",
    ] {
        assert!(stdout.contains(expected), "missing {expected}:\n{stdout}");
    }
    let again = run(&["--format", "json", testdata("ready").to_str().unwrap()]);
    assert_eq!(
        out.stdout, again.stdout,
        "output must not depend on anything but the input"
    );
}

#[test]
fn an_unreadable_report_is_named_and_does_not_hide_the_rest() {
    let dir = std::env::temp_dir().join(format!("dmarcwatch-cli-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let broken = dir.join("broken.xml");
    std::fs::write(&broken, "<feedback><report_metadata>").unwrap();
    let good = testdata("ready").join("google.com!example.org!week1.xml");
    let out = run(&[good.to_str().unwrap(), broken.to_str().unwrap()]);
    let _ = std::fs::remove_dir_all(&dir);

    assert_eq!(out.status.code(), Some(2));
    let stderr = text(&out.stderr);
    assert!(
        stderr.contains("broken.xml") && stderr.contains("document ends inside <report_metadata>"),
        "{stderr}"
    );
    assert!(
        stderr.contains("1 report(s) could not be read and are not in the figures above"),
        "{stderr}"
    );
    assert!(
        text(&out.stdout).contains("example.org"),
        "the readable report is still analysed"
    );
}

#[test]
fn a_missing_file_is_a_clear_error() {
    let out = run(&["definitely-not-here.xml"]);
    assert_eq!(out.status.code(), Some(2));
    let stderr = text(&out.stderr);
    assert!(
        stderr.contains("definitely-not-here.xml: no such file"),
        "{stderr}"
    );
}

#[test]
fn usage_errors_exit_2() {
    for args in [
        vec![],
        vec!["--bogus", "x"],
        vec!["--format", "xml", "x"],
        vec!["--max-fail-share", "-1", "x"],
        vec!["--max-fail-share", "101", "x"],
        vec!["--min-messages", "1.5", "x"],
    ] {
        let out = run(&args);
        assert_eq!(out.status.code(), Some(2), "{args:?}");
        assert!(text(&out.stderr).contains("usage: dmarcwatch"), "{args:?}");
    }
}

#[test]
fn an_oversized_file_is_refused_without_being_read_whole() {
    let path = std::env::temp_dir().join(format!("dmarcwatch-big-{}.xml", std::process::id()));
    {
        use std::io::Write;
        let mut f = std::fs::File::create(&path).unwrap();
        let chunk = vec![b' '; 1024 * 1024];
        for _ in 0..65 {
            f.write_all(&chunk).unwrap();
        }
    }
    let out = run(&[path.to_str().unwrap()]);
    let _ = std::fs::remove_file(&path);
    assert_eq!(out.status.code(), Some(2));
    assert!(
        text(&out.stderr).contains("file is larger than 64 MiB; refusing it"),
        "{}",
        text(&out.stderr)
    );
}
