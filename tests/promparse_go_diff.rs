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
use std::path::{Path, PathBuf};

use expfmt::textparse::{Entry, LabelsBuffer, Parser, PromParser};

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

fn render(input: &[u8]) -> Vec<u8> {
    let mut parser = PromParser::new(input);
    let mut labels = LabelsBuffer::new();
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
                let (name, metric_type) = parser.metric_type();
                out.extend_from_slice(b"type ");
                quote(&mut out, name);
                write!(out, " {}", metric_type.as_str()).unwrap();
            }
            Entry::Comment => {
                out.extend_from_slice(b"comment ");
                quote(&mut out, parser.comment());
            }
            Entry::Series => {
                let (series, timestamp, value) = parser.series();
                out.extend_from_slice(b"series ");
                quote(&mut out, series);
                let timestamp = timestamp.map_or("-".to_owned(), |millis| millis.to_string());
                write!(out, " {:016x} {timestamp}", value.to_bits()).unwrap();
                parser.labels(&mut labels);
                for (name, value) in labels.iter() {
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

/// Expected files sit under `testdata/promparse/` at the same relative path as their input.
fn expected_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            expected_files(&path, out);
        } else {
            out.push(path);
        }
    }
}

#[test]
fn matches_go_promparse_output() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata");
    let mut expected = Vec::new();
    expected_files(&root.join("promparse"), &mut expected);
    assert!(
        !expected.is_empty(),
        "no Go expected files in testdata/promparse"
    );
    for path in expected {
        let input = path.strip_prefix(root.join("promparse")).unwrap();
        let want = fs::read(&path).unwrap();
        let got = render(&fs::read(root.join(input)).unwrap());
        // Compare as text first for a readable diff, then as bytes for non-UTF-8 input.
        assert_eq!(
            String::from_utf8_lossy(&got),
            String::from_utf8_lossy(&want),
            "fixture {}",
            input.display()
        );
        assert_eq!(got, want, "fixture {}", input.display());
    }
}
