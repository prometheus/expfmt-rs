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

//! Prometheus `io.prometheus.client` protobuf data transfer objects (`MetricFamily` and related
//! message types) compiled from [`io.prometheus.client`](https://buf.build/prometheus/prometheus/docs/main%3Aio.prometheus.client)
//! ([`prompb/io/prometheus/client/metrics.proto`](https://github.com/prometheus/prometheus/blob/main/prompb/io/prometheus/client/metrics.proto)).

/// Generated `io.prometheus.client` protobuf structs and enums.
#[allow(missing_docs, clippy::all)]
#[path = "dto/io.prometheus.client.rs"]
pub mod proto;

pub use proto::{
    Bucket, BucketSpan, Counter, Exemplar, Gauge, Histogram, LabelPair, Metric, MetricFamily,
    MetricType, Quantile, Summary, Untyped,
};

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use prost::Message;

    use super::*;

    #[test]
    fn generated_proto_is_up_to_date() {
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let proto_file = manifest_dir.join("proto/io/prometheus/client/metrics.proto");
        let proto_include = manifest_dir.join("proto");
        let checked_in_path = manifest_dir.join("src/dto/io.prometheus.client.rs");

        let out_dir =
            std::env::temp_dir().join(format!("expfmt-proto-test-{}", std::process::id()));
        fs::create_dir_all(&out_dir).expect("temp out_dir should be created");

        prost_build::Config::new()
            .out_dir(&out_dir)
            .compile_protos(&[&proto_file], &[&proto_include])
            .expect("prost-build should compile metrics.proto");

        let generated_path = out_dir.join("io.prometheus.client.rs");
        let generated =
            fs::read_to_string(&generated_path).expect("generated file should be readable");
        let _ = fs::remove_dir_all(&out_dir);

        if std::env::var_os("UPDATE_PROTO").is_some() {
            fs::write(&checked_in_path, &generated).expect("should update checked-in proto file");
        }

        let checked_in =
            fs::read_to_string(&checked_in_path).expect("checked-in proto file should be readable");
        assert_eq!(
            checked_in, generated,
            "src/dto/io.prometheus.client.rs is out of date with proto/io/prometheus/client/metrics.proto; \
             re-run with UPDATE_PROTO=1 cargo test"
        );
    }

    #[test]
    fn encode_decode_length_delimited_metric_family() {
        let family = MetricFamily {
            name: "http_requests_total".to_owned(),
            help: "Total number of HTTP requests.".to_owned(),
            r#type: MetricType::Counter as i32,
            unit: String::new(),
            metric: vec![Metric {
                label: vec![LabelPair {
                    name: "method".to_owned(),
                    value: "GET".to_owned(),
                }],
                counter: Some(Counter {
                    value: 42.0,
                    exemplar: None,
                    start_timestamp: None,
                }),
                timestamp_ms: 1_700_000_000_000,
                ..Default::default()
            }],
        };

        let mut buf = Vec::new();
        family
            .encode_length_delimited(&mut buf)
            .expect("length-delimited encode should succeed");

        let decoded = MetricFamily::decode_length_delimited(buf.as_slice())
            .expect("length-delimited decode should succeed");
        assert_eq!(decoded, family);
        assert_eq!(decoded.r#type(), MetricType::Counter);
    }

    #[test]
    fn encode_decode_native_histogram_fields() {
        let family = MetricFamily {
            name: "request_duration_seconds".to_owned(),
            help: "Request latency distribution.".to_owned(),
            r#type: MetricType::Histogram as i32,
            unit: "seconds".to_owned(),
            metric: vec![Metric {
                histogram: Some(Histogram {
                    sample_count: 10,
                    sample_sum: 12.5,
                    schema: 3,
                    zero_threshold: 0.001,
                    zero_count: 2,
                    positive_span: vec![BucketSpan {
                        offset: 0,
                        length: 2,
                    }],
                    positive_delta: vec![5, -2],
                    ..Default::default()
                }),
                ..Default::default()
            }],
        };

        let encoded = family.encode_to_vec();
        let decoded = MetricFamily::decode(encoded.as_slice()).expect("decode should succeed");
        assert_eq!(decoded, family);
    }
}
