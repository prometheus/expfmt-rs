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

use std::fs;
use std::io::Write;
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

fn quote(out: &mut Vec<u8>, bytes: &[u8]) {
    out.push(b'"');
    for &byte in bytes {
        match byte {
            b'\\' => out.extend_from_slice(b"\\\\"),
            b'"' => out.extend_from_slice(b"\\\""),
            0..0x20 | 0x7f => out.extend_from_slice(format!("\\x{byte:02x}").as_bytes()),
            _ => out.push(byte),
        }
    }
    out.push(b'"');
}

/// Go's `strconv.FormatFloat(v, 'e', -1, 64)`, with Prometheus spellings for NaN and infinities.
fn format_value(val: f64) -> String {
    if val.is_nan() {
        return "NaN".to_owned();
    }
    if val.is_infinite() {
        return if val > 0.0 { "+Inf" } else { "-Inf" }.to_owned();
    }
    let mut scientific = format!("{val:e}");
    // Go picks the correctly rounded digits among the shortest forms, Rust may not,
    // so keep Rust's shortest digit count and round again to it.
    let mantissa = scientific.split('e').next().unwrap();
    let precision = mantissa.bytes().filter(u8::is_ascii_digit).count() - 1;
    scientific = format!("{val:.precision$e}");
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

fn render(input: &[u8]) -> Vec<u8> {
    let mut parser = PromParser::new(input);
    let mut buf = LabelsBuffer::new();
    let mut out = Vec::new();
    loop {
        let entry = match parser.next_entry() {
            Ok(Some(entry)) => entry,
            Ok(None) => return out,
            Err(_) => {
                out.extend_from_slice(b"error\n");
                return out;
            }
        };
        match entry {
            Entry::Help => {
                let (name, text) = parser.help();
                out.extend_from_slice(b"help ");
                quote(&mut out, name);
                out.push(b' ');
                quote(&mut out, &text);
            }
            Entry::Type => {
                let (name, mtype) = parser.metric_type();
                out.extend_from_slice(b"type ");
                quote(&mut out, name);
                write!(out, " {}", type_name(mtype)).unwrap();
            }
            Entry::Comment => {
                out.extend_from_slice(b"comment ");
                quote(&mut out, parser.comment());
            }
            Entry::Series => {
                let (series, ts, val) = parser.series();
                out.extend_from_slice(b"series ");
                quote(&mut out, series);
                let ts = ts.map_or("-".to_owned(), |ts| ts.to_string());
                write!(out, " {} {ts}", format_value(val)).unwrap();
                if parser.labels(&mut buf).is_err() {
                    out.extend_from_slice(b"\nerror\n");
                    return out;
                }
                for (name, value) in buf.iter() {
                    out.push(b' ');
                    quote(&mut out, name.as_bytes());
                    out.push(b'=');
                    quote(&mut out, value.as_bytes());
                }
            }
            other => panic!("unexpected entry {other:?}"),
        }
        out.push(b'\n');
    }
}

#[test]
fn matches_go_promparse_output() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata");
    for (input, expected) in FIXTURES {
        let input_bytes = fs::read(root.join(input)).unwrap();
        let want = fs::read(root.join(expected)).unwrap();
        let got = render(&input_bytes);
        // Compare as text first for a readable diff, then as bytes for non-UTF-8 input.
        assert_eq!(
            String::from_utf8_lossy(&got),
            String::from_utf8_lossy(&want),
            "fixture {input}"
        );
        assert_eq!(got, want, "fixture {input}");
    }
}

#[test]
fn every_go_expected_file_is_checked() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/promparse");
    let mut on_disk: Vec<String> = fs::read_dir(dir)
        .unwrap()
        .map(|entry| format!("promparse/{}", entry.unwrap().file_name().to_string_lossy()))
        .collect();
    on_disk.sort();
    let mut checked: Vec<String> = FIXTURES
        .iter()
        .map(|(_, expected)| expected.to_string())
        .collect();
    checked.sort();
    assert_eq!(on_disk, checked);
}

#[test]
fn format_value_matches_go() {
    let cases = [
        (4.9351e-05, "4.9351e-05"),
        (1.0, "1e+00"),
        (2.279966416e9, "2.279966416e+09"),
        (123456.0, "1.23456e+05"),
        (1e-300, "1e-300"),
        (1453167548838524.2, "1.4531675488385242e+15"),
        (f64::NEG_INFINITY, "-Inf"),
    ];
    for (val, want) in cases {
        assert_eq!(format_value(val), want);
    }
}
