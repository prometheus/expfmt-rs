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

//! Smoke tests verifying the synced `testdata/` corpus from `prometheus/common/expfmt`
//! and `prometheus/prometheus/model/textparse`.

use std::fs;
use std::path::Path;

#[test]
fn synced_testdata_corpus_is_present() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata");
    let manifest_path = root.join("manifest.json");
    let manifest = fs::read_to_string(&manifest_path).expect("testdata/manifest.json must exist");
    assert!(manifest.contains("github.com/prometheus/common"));
    assert!(manifest.contains("github.com/prometheus/prometheus"));

    let expected_files = [
        "expfmt/protobuf",
        "expfmt/protobuf-multimessage",
        "expfmt/text",
        "textparse/TestPromParse.prom.txt",
        "textparse/TestOpenMetricsParse.om.txt",
        "textparse/TestOpenMetrics2Parse.om2.txt",
        "textparse/1histogram.om.txt",
        "textparse/alltypes.237mfs.prom.txt",
        "textparse/alltypes.5mfs.om.txt",
        "textparse/alltypes.om2.txt",
    ];

    for rel in expected_files {
        let path = root.join(rel);
        let metadata = fs::metadata(&path).unwrap_or_else(|e| panic!("missing {rel}: {e}"));
        assert!(metadata.len() > 0, "fixture {rel} must not be empty");
    }
}

#[cfg(feature = "dto")]
#[test]
fn decode_upstream_expfmt_protobuf_fixtures() {
    use expfmt::dto::MetricFamily;
    use prost::Message;

    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/expfmt");

    for fixture in ["protobuf", "protobuf-multimessage"] {
        let raw = fs::read(root.join(fixture)).expect("protobuf fixture should be readable");
        let mut cursor: &[u8] = &raw;
        let mut families = Vec::new();
        while !cursor.is_empty() {
            let mf = MetricFamily::decode_length_delimited(&mut cursor)
                .unwrap_or_else(|e| panic!("failed to decode {fixture}: {e}"));
            assert!(
                !mf.name.is_empty(),
                "decoded MetricFamily in {fixture} must have a name"
            );
            families.push(mf);
        }
        assert!(
            !families.is_empty(),
            "fixture {fixture} must yield at least one MetricFamily"
        );
    }
}
