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
//! message types) compiled from [`metrics.proto`](https://github.com/prometheus/client_model/blob/master/io/prometheus/client/metrics.proto).

/// Generated `io.prometheus.client` protobuf structs and enums.
#[allow(missing_docs, clippy::all)]
pub mod proto {
    include!(concat!(env!("OUT_DIR"), "/io.prometheus.client.rs"));
}

pub use proto::{
    Bucket, BucketSpan, Counter, Exemplar, Gauge, Histogram, LabelPair, Metric, MetricFamily,
    MetricType, Quantile, Summary, Untyped,
};

#[cfg(test)]
mod tests {
    use prost::Message;

    use super::*;

    #[test]
    fn encode_decode_length_delimited_metric_family() {
        let family = MetricFamily {
            name: Some("http_requests_total".to_owned()),
            help: Some("Total number of HTTP requests.".to_owned()),
            r#type: Some(MetricType::Counter as i32),
            unit: None,
            metric: vec![Metric {
                label: vec![LabelPair {
                    name: Some("method".to_owned()),
                    value: Some("GET".to_owned()),
                }],
                counter: Some(Counter {
                    value: Some(42.0),
                    exemplar: None,
                    created_timestamp: None,
                }),
                timestamp_ms: Some(1_700_000_000_000),
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
            name: Some("request_duration_seconds".to_owned()),
            help: Some("Request latency distribution.".to_owned()),
            r#type: Some(MetricType::Histogram as i32),
            unit: Some("seconds".to_owned()),
            metric: vec![Metric {
                histogram: Some(Histogram {
                    sample_count: Some(10),
                    sample_sum: Some(12.5),
                    schema: Some(3),
                    zero_threshold: Some(0.001),
                    zero_count: Some(2),
                    positive_span: vec![BucketSpan {
                        offset: Some(0),
                        length: Some(2),
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
