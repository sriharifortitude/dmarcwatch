use dmarcwatch::aggregate;
use dmarcwatch::analyze::{analyze, Options};
use dmarcwatch::{input, render};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

const USAGE: &str = "\
usage: dmarcwatch [--format terminal|json] [--max-fail-share PERCENT] [--min-days N]
                  [--min-messages N] [--fail-if-not-ready] PATH...

  PATH                an aggregate report (.xml, .gz or .zip) or a directory of them
  --format            output format (default: terminal)
  --max-fail-share    largest percentage of mail that may fail for a fixable reason
                      before a domain is not ready (default: 0.5)
  --min-days          fewest days the reports must span (default: 7)
  --min-messages      fewest messages the reports must cover (default: 100)
  --fail-if-not-ready exit 1 if any domain is not ready for a stricter policy

exit codes: 0 reports read (and ready, with --fail-if-not-ready), 1 a domain is not
ready, 2 usage error or a report that could not be read";

enum Format {
    Terminal,
    Json,
}

struct Args {
    format: Format,
    options: Options,
    fail_if_not_ready: bool,
    paths: Vec<PathBuf>,
}

fn main() -> ExitCode {
    match run(std::env::args().skip(1).collect()) {
        Ok(code) => code,
        Err(message) => {
            eprintln!("dmarcwatch: {message}\n\n{USAGE}");
            ExitCode::from(2)
        }
    }
}

fn parse_args(args: Vec<String>) -> Result<Args, String> {
    let mut parsed = Args {
        format: Format::Terminal,
        options: Options::default(),
        fail_if_not_ready: false,
        paths: Vec::new(),
    };
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        let (flag, inline) = match arg.split_once('=') {
            Some((f, v)) if f.starts_with("--") => (f.to_string(), Some(v.to_string())),
            _ => (arg.clone(), None),
        };
        let mut value = |name: &str| {
            inline
                .clone()
                .or_else(|| args.next())
                .ok_or_else(|| format!("{name} needs a value"))
        };
        match flag.as_str() {
            "--format" => {
                parsed.format = match value("--format")?.as_str() {
                    "terminal" => Format::Terminal,
                    "json" => Format::Json,
                    other => return Err(format!("unknown format {other:?}")),
                }
            }
            "--max-fail-share" => {
                let v = number(&value("--max-fail-share")?, "--max-fail-share")?;
                if v > 100.0 {
                    return Err("--max-fail-share is a percentage between 0 and 100".into());
                }
                parsed.options.max_fail_share = v / 100.0;
            }
            "--min-days" => parsed.options.min_days = number(&value("--min-days")?, "--min-days")?,
            "--min-messages" => {
                let v = value("--min-messages")?;
                parsed.options.min_messages = v
                    .parse()
                    .map_err(|_| format!("--min-messages {v:?} is not a whole number"))?;
            }
            "--fail-if-not-ready" => parsed.fail_if_not_ready = true,
            "-h" | "--help" => return Err("help requested".into()),
            f if f.starts_with("--") => return Err(format!("unknown option {f}")),
            _ => parsed.paths.push(PathBuf::from(arg)),
        }
    }
    if parsed.paths.is_empty() {
        return Err("no report given".into());
    }
    Ok(parsed)
}

fn number(text: &str, flag: &str) -> Result<f64, String> {
    match text.parse::<f64>() {
        Ok(v) if v.is_finite() && v >= 0.0 => Ok(v),
        _ => Err(format!("{flag} {text:?} is not a non-negative number")),
    }
}

/// Files to read: the paths given, with directories expanded one level in name order.
fn expand(paths: &[PathBuf]) -> Result<Vec<PathBuf>, String> {
    let mut files = Vec::new();
    for path in paths {
        if path.is_dir() {
            let mut entries: Vec<PathBuf> = std::fs::read_dir(path)
                .map_err(|e| format!("{}: {e}", path.display()))?
                .filter_map(Result::ok)
                .map(|e| e.path())
                .filter(|p| p.is_file() && is_report_name(p))
                .collect();
            entries.sort();
            files.extend(entries);
        } else {
            files.push(path.clone());
        }
    }
    Ok(files)
}

fn is_report_name(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| matches!(e.to_ascii_lowercase().as_str(), "xml" | "gz" | "zip"))
}

fn run(args: Vec<String>) -> Result<ExitCode, String> {
    let args = parse_args(args)?;
    let files = expand(&args.paths)?;
    let mut reports = Vec::new();
    let mut unreadable = 0usize;
    for file in &files {
        let read = input::read_file(file).and_then(|bytes| input::documents(&bytes));
        let documents = match read {
            Ok(d) => d,
            Err(message) => {
                eprintln!("dmarcwatch: {}: {message}", file.display());
                unreadable += 1;
                continue;
            }
        };
        for (label, xml) in documents {
            match aggregate::parse(&xml) {
                Ok(report) => reports.push(report),
                Err(e) => {
                    eprintln!("dmarcwatch: {} ({label}): {e}", file.display());
                    unreadable += 1;
                }
            }
        }
    }
    if reports.is_empty() {
        return Err("no readable aggregate report".into());
    }

    let analysis = analyze(reports, args.options);
    match args.format {
        Format::Terminal => print!("{}", render::terminal(&analysis)),
        Format::Json => println!(
            "{}",
            serde_json::to_string_pretty(&render::json(&analysis)).expect("json value serialises")
        ),
    }

    if unreadable > 0 {
        eprintln!(
            "dmarcwatch: {unreadable} report(s) could not be read and are not in the figures above"
        );
        return Ok(ExitCode::from(2));
    }
    if args.fail_if_not_ready && analysis.domains.iter().any(|d| !d.verdict.ready) {
        return Ok(ExitCode::from(1));
    }
    Ok(ExitCode::SUCCESS)
}
