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

//! Layer 0 zero-copy streaming parsers, mirroring
//! [`prometheus/prometheus/model/textparse`](https://github.com/prometheus/prometheus/tree/main/model/textparse).

use std::borrow::Cow;

#[cfg(test)]
mod go_diff_tests;
mod promparse;

pub use promparse::PromParser;

/// Label name under which [`Parser::labels`] stores the metric name.
pub const METRIC_NAME_LABEL: &str = "__name__";

/// Label name for the upper bound of a classic histogram bucket, Go's `model.BucketLabel`.
pub const BUCKET_LABEL: &str = "le";

/// Label name for the quantile of a summary sample, Go's `model.QuantileLabel`.
pub const QUANTILE_LABEL: &str = "quantile";

/// Kind of the entry the parser is positioned on after [`Parser::next_entry`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Entry {
    /// A `# TYPE` line. Read it with [`Parser::metric_type`].
    Type,
    /// A `# HELP` line. Read it with [`Parser::help`].
    Help,
    /// Any other comment line. Read it with [`Parser::comment`].
    Comment,
    /// A sample with a float64 value. Read it with [`Parser::series`] and [`Parser::labels`].
    Series,
}

/// Metric type declared by a `# TYPE` line.
///
/// Mirrors `model.MetricType` in `prometheus/common/model`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum MetricType {
    /// `untyped` in Prometheus text, `unknown` in OpenMetrics.
    #[default]
    Unknown,
    /// `counter`.
    Counter,
    /// `gauge`.
    Gauge,
    /// `histogram`.
    Histogram,
    /// `summary`.
    Summary,
}

impl MetricType {
    /// Returns Go's `model.MetricType` string, for example `"counter"` or `"unknown"`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Counter => "counter",
            Self::Gauge => "gauge",
            Self::Histogram => "histogram",
            Self::Summary => "summary",
        }
    }
}

/// Error returned by [`Parser`] implementations.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ParseError {
    /// The input does not match the exposition format grammar.
    #[error("{expected} at byte {offset}")]
    UnexpectedToken {
        /// What the parser expected, for example `"expected label value"`.
        expected: &'static str,
        /// Byte offset of the offending token in the input.
        offset: usize,
    },

    /// A `# TYPE` line names an unknown metric type.
    #[error("invalid metric type {0:?}")]
    InvalidMetricType(String),

    /// A help text, label name, or label value is not valid UTF-8.
    #[error("invalid UTF-8 at byte {offset}")]
    InvalidUtf8 {
        /// Byte offset of the start of the invalid string in the input.
        offset: usize,
    },

    /// A sample value is not a valid float.
    #[error("invalid sample value {0:?}")]
    InvalidValue(String),

    /// A sample timestamp is not a valid int64.
    #[error("invalid timestamp {0:?}")]
    InvalidTimestamp(String),

    /// A series has no metric name, or sets it twice.
    #[error("invalid metric name at byte {offset}")]
    InvalidMetricName {
        /// Byte offset of the start of the series in the input.
        offset: usize,
    },
}

/// Reusable buffer that [`Parser::labels`] fills with the labels of the current sample.
///
/// Names and values borrow from the input unless they contain escape sequences
/// or need normalization, so a reused buffer does not allocate per sample.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LabelsBuffer<'a> {
    labels: Vec<(Cow<'a, str>, Cow<'a, str>)>,
}

impl<'a> LabelsBuffer<'a> {
    /// Creates an empty buffer.
    pub fn new() -> Self {
        Self::default()
    }

    /// Removes all labels and keeps the allocated capacity.
    pub fn clear(&mut self) {
        self.labels.clear();
    }

    /// Appends a label.
    pub fn push(&mut self, name: Cow<'a, str>, value: Cow<'a, str>) {
        self.labels.push((name, value));
    }

    /// Sorts the labels by name.
    pub fn sort(&mut self) {
        self.labels
            .sort_unstable_by(|left, right| left.0.cmp(&right.0));
    }

    /// Returns the value of the label `name`, if present.
    pub fn get(&self, name: &str) -> Option<&str> {
        self.iter()
            .find(|(label_name, _)| *label_name == name)
            .map(|(_, value)| value)
    }

    /// Iterates over `(name, value)` pairs.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.labels
            .iter()
            .map(|(name, value)| (name.as_ref(), value.as_ref()))
    }

    /// Returns the labels with their `Cow` kind, so callers can keep `Cow::Borrowed`
    /// slices for `'a` after [`LabelsBuffer::clear`].
    pub fn as_slice(&self) -> &[(Cow<'a, str>, Cow<'a, str>)] {
        &self.labels
    }

    /// Returns the number of labels.
    pub fn len(&self) -> usize {
        self.labels.len()
    }

    /// Returns `true` if the buffer holds no labels.
    pub fn is_empty(&self) -> bool {
        self.labels.is_empty()
    }
}

/// Streaming parser over an exposition payload, mirroring Go's `textparse.Parser`.
///
/// Accessors return unspecified values when called for a different [`Entry`] kind.
pub trait Parser<'a> {
    /// Advances to the next entry in the exposition stream, returning `Ok(None)` at EOF.
    fn next_entry(&mut self) -> Result<Option<Entry>, ParseError>;

    /// Returns the metric name and unescaped help text of the current [`Entry::Help`].
    fn help(&self) -> (&'a [u8], Cow<'a, [u8]>);

    /// Returns the metric name and type of the current [`Entry::Type`].
    fn metric_type(&self) -> (&'a [u8], MetricType);

    /// Returns the text of the current [`Entry::Comment`], including the leading `#`.
    fn comment(&self) -> &'a [u8];

    /// Returns the raw series bytes, optional sample timestamp in ms, and float64 value.
    fn series(&self) -> (&'a [u8], Option<i64>, f64);

    /// Clears `buf` and fills it with the current sample's labels, sorted by name, matching Go:
    /// the metric name is stored under [`METRIC_NAME_LABEL`], and `le` on histograms and
    /// `quantile` on summaries use OpenMetrics float formatting.
    fn labels(&self, buf: &mut LabelsBuffer<'a>);
}
