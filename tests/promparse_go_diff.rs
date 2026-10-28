// Copyright 2026 The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Compares `PromParser` output with Go's `textparse.PromParser` output stored in `testdata/promparse`.

use std::fmt::Write;
use std::fs;
use std::path::Path;

use expfmt::textparse::{Entry, LabelsBuffer, MetricType, Parser, PromParser};

const FIXTURES: &[(&str, &str)] = &[
    (
        "textparse/TestPromParse.prom.txt",
        "promparse/TestPromParse.prom.txt.txt",
    ),
    (
        "textparse/alltypes.237mfs.prom.txt",
        "promparse/alltypes.237mfs.prom.txt.txt",
    ),
    (
        "textparse/alltypes.237mfs.nometa.prom.txt",
        "promparse/alltypes.237mfs.nometa.prom.txt.txt",
    ),
    ("expfmt/text", "promparse/expfmt_text.txt"),
];

fn quote(bytes: &[u8]) -> String {
    let mut out = String::from("\"");
    let mut raw = Vec::new();
    for &byte in bytes {
        match byte {
            b'\\' => raw.extend_from_slice(b"\\\\"),
            b'"' => raw.extend_from_slice(b"\\\""),
            0..0x20 | 0x7f => raw.extend_from_slice(format!("\\x{byte:02x}").as_bytes()),
            _ => raw.push(byte),
        }
    }
    out.push_str(&String::from_utf8_lossy(&raw));
    out.push('"');
    out
}

/// Go's `strconv.FormatFloat(v, 'e', -1, 64)`, with Prometheus spellings for NaN and infinities.
fn format_value(val: f64) -> String {
    if val.is_nan() {
        return "NaN".to_owned();
    }
    if val.is_infinite() {
        return if val > 0.0 { "+Inf" } else { "-Inf" }.to_owned();
    }
    let scientific = format!("{val:e}");
    let (mantissa, exp) = scientific.split_once('e').unwrap();
    let exp: i32 = exp.parse().unwrap();
    let sign = if exp < 0 { '-' } else { '+' };
    format!("{mantissa}e{sign}{:02}", exp.abs())
}

fn type_name(mtype: MetricType) -> &'static str {
    match mtype {
        MetricType::Counter => "counter",
        MetricType::Gauge => "gauge",
        MetricType::Histogram => "histogram",
        MetricType::Summary => "summary",
        _ => "unknown",
    }
}

fn render(input: &[u8]) -> String {
    let mut parser = PromParser::new(input);
    let mut buf = LabelsBuffer::new();
    let mut out = String::new();
    loop {
        let entry = match parser.next_entry() {
            Ok(Some(entry)) => entry,
            Ok(None) => return out,
            Err(_) => {
                out.push_str("error\n");
                return out;
            }
        };
        match entry {
            Entry::Help => {
                let (name, text) = parser.help();
                writeln!(out, "help {} {}", quote(name), quote(&text)).unwrap();
            }
            Entry::Type => {
                let (name, mtype) = parser.metric_type();
                writeln!(out, "type {} {}", quote(name), type_name(mtype)).unwrap();
            }
            Entry::Comment => writeln!(out, "comment {}", quote(parser.comment())).unwrap(),
            Entry::Series => {
                let (series, ts, val) = parser.series();
                let ts = ts.map_or("-".to_owned(), |ts| ts.to_string());
                write!(out, "series {} {} {ts}", quote(series), format_value(val)).unwrap();
                if parser.labels(&mut buf).is_err() {
                    out.push_str("\nerror\n");
                    return out;
                }
                for (name, value) in buf.iter() {
                    write!(
                        out,
                        " {}={}",
                        quote(name.as_bytes()),
                        quote(value.as_bytes())
                    )
                    .unwrap();
                }
                out.push('\n');
            }
            other => panic!("unexpected entry {other:?}"),
        }
    }
}

#[test]
fn matches_go_promparse_output() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata");
    for (input, expected) in FIXTURES {
        let input_bytes = fs::read(root.join(input)).unwrap();
        let want = fs::read_to_string(root.join(expected)).unwrap();
        assert_eq!(render(&input_bytes), want, "fixture {input}");
    }
}

#[test]
fn format_value_matches_go() {
    let cases = [
        (4.9351e-05, "4.9351e-05"),
        (1.0, "1e+00"),
        (2.279966416e9, "2.279966416e+09"),
        (123456.0, "1.23456e+05"),
        (1e-300, "1e-300"),
        (f64::NEG_INFINITY, "-Inf"),
    ];
    for (val, want) in cases {
        assert_eq!(format_value(val), want);
    }
}
