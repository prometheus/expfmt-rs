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

//! Prometheus text format 0.0.4 parser, a port of
//! [`promparse.go`](https://github.com/prometheus/prometheus/blob/main/model/textparse/promparse.go).

use std::borrow::Cow;

use super::float::{FloatBuf, common_openmetrics_float, format_openmetrics_float, parse_go_float};
use super::promlex::{Lexer, Token};
use super::{
    BUCKET_LABEL, Entry, LabelsBuffer, METRIC_NAME_LABEL, MetricType, ParseError, Parser,
    QUANTILE_LABEL,
};

/// Go's `value.NormalNaN`, the canonical NaN bit pattern Prometheus stores.
const NORMAL_NAN: u64 = 0x7ff8_0000_0000_0001;

/// Zero-copy parser for the Prometheus text exposition format 0.0.4.
///
/// Mirrors Go's `textparse.NewPromParser` with type and unit labels disabled.
pub struct PromParser<'a> {
    lexer: Lexer<'a>,
    series: &'a [u8],
    text: &'a [u8],
    /// The type from the last `# TYPE` line, which Go keeps across metric families.
    last_type: MetricType,
    value: f64,
    timestamp: Option<i64>,
    line_start: usize,
    name: Option<&'a [u8]>,
    /// Escaped label names and values, without quotes, already checked to be UTF-8.
    labels: Vec<(&'a str, &'a str)>,
}

impl<'a> PromParser<'a> {
    /// Creates a parser over `input`.
    pub fn new(input: &'a [u8]) -> Self {
        Self {
            lexer: Lexer::new(input),
            series: b"",
            text: b"",
            last_type: MetricType::Unknown,
            value: 0.0,
            timestamp: None,
            line_start: 0,
            name: None,
            labels: Vec::new(),
        }
    }

    fn next_token(&mut self) -> Token {
        loop {
            let token = self.lexer.lex();
            if token != Token::Whitespace {
                return token;
            }
        }
    }

    fn unexpected(&self, expected: &'static str) -> ParseError {
        ParseError::UnexpectedToken {
            expected,
            offset: self.lexer.token_start,
        }
    }

    fn parse_metadata(&mut self, kind: Token) -> Result<Entry, ParseError> {
        if self.next_token() != Token::MName {
            return Err(self.unexpected("expected metric name"));
        }
        let (mut start, mut end) = (self.lexer.token_start, self.lexer.pos);
        if self.lexer.input[start] == b'"' && self.lexer.input[end - 1] == b'"' {
            start += 1;
            end -= 1;
        }
        self.name = Some(&self.lexer.input[start..end]);
        if self.next_token() != Token::Text {
            return Err(self.unexpected("expected text"));
        }
        let text = self.lexer.token();
        self.text = text.get(1..).unwrap_or_default();
        let entry = if kind == Token::Type {
            self.last_type = parse_metric_type(self.text)?;
            Entry::Type
        } else {
            if std::str::from_utf8(self.text).is_err() {
                return Err(ParseError::InvalidUtf8 {
                    offset: self.lexer.token_start,
                });
            }
            Entry::Help
        };
        if self.next_token() != Token::Linebreak {
            return Err(self.unexpected("expected linebreak after metadata"));
        }
        Ok(entry)
    }

    fn parse_comment(&mut self) -> Result<Entry, ParseError> {
        self.text = self.lexer.token();
        if self.next_token() != Token::Linebreak {
            return Err(self.unexpected("expected linebreak after comment"));
        }
        Ok(Entry::Comment)
    }

    /// Parses a sample line that starts with a metric name or with `{`.
    fn parse_series(&mut self, first: Token) -> Result<Entry, ParseError> {
        let mut token = first;
        if first == Token::MName {
            // Go uses the line start, so leading blanks become part of the name.
            self.series = self.consumed_line();
            self.name = Some(self.series);
            token = self.next_token();
        }
        if token == Token::BraceOpen {
            self.parse_label_values()?;
            self.series = self.consumed_line();
            token = self.next_token();
        }
        self.parse_metric_suffix(token)
    }

    /// Returns the bytes of the current line that the lexer has consumed so far.
    fn consumed_line(&self) -> &'a [u8] {
        &self.lexer.input[self.line_start..self.lexer.pos]
    }

    fn parse_label_values(&mut self) -> Result<(), ParseError> {
        let mut token = self.next_token();
        loop {
            let quoted = match token {
                Token::BraceClose => return Ok(()),
                Token::LName => false,
                Token::QString => true,
                _ => return Err(self.unexpected("expected label name")),
            };
            let name = self.token_str(quoted)?;
            token = self.next_token();
            if quoted && matches!(token, Token::Comma | Token::BraceClose) {
                if self.name.is_some() {
                    return Err(ParseError::InvalidMetricName {
                        offset: self.line_start,
                    });
                }
                self.name = Some(name.as_bytes());
                if token == Token::BraceClose {
                    return Ok(());
                }
                token = self.next_token();
                continue;
            }
            if token != Token::Equal {
                return Err(self.unexpected("expected equal"));
            }
            if self.next_token() != Token::LValue {
                return Err(self.unexpected("expected label value"));
            }
            self.labels.push((name, self.token_str(true)?));
            token = self.next_token();
            if token == Token::Comma {
                token = self.next_token();
            }
        }
    }

    /// Returns the current token as UTF-8, without its quotes when `quoted`.
    fn token_str(&self, quoted: bool) -> Result<&'a str, ParseError> {
        let raw = self.lexer.token();
        let raw = if quoted { &raw[1..raw.len() - 1] } else { raw };
        std::str::from_utf8(raw).map_err(|_| ParseError::InvalidUtf8 {
            offset: self.lexer.token_start,
        })
    }

    fn parse_metric_suffix(&mut self, token: Token) -> Result<Entry, ParseError> {
        if self.name.is_none() {
            return Err(ParseError::InvalidMetricName {
                offset: self.line_start,
            });
        }
        if token != Token::Value {
            return Err(self.unexpected("expected value after metric"));
        }
        let raw = self.lexer.token();
        let value = parse_sample_value(raw)
            .ok_or_else(|| ParseError::InvalidValue(String::from_utf8_lossy(raw).into_owned()))?;
        self.value = if value.is_nan() {
            f64::from_bits(NORMAL_NAN)
        } else {
            value
        };
        self.timestamp = None;
        match self.next_token() {
            Token::Linebreak => {}
            Token::Timestamp => {
                let raw = self.lexer.token();
                let timestamp = std::str::from_utf8(raw)
                    .ok()
                    .and_then(|digits| digits.parse().ok())
                    .ok_or_else(|| {
                        ParseError::InvalidTimestamp(String::from_utf8_lossy(raw).into_owned())
                    })?;
                self.timestamp = Some(timestamp);
                if self.next_token() != Token::Linebreak {
                    return Err(self.unexpected("expected linebreak after timestamp"));
                }
            }
            _ => return Err(self.unexpected("expected timestamp or linebreak")),
        }
        Ok(Entry::Series)
    }

    fn metric_name(&self) -> &'a [u8] {
        self.name.unwrap_or_default()
    }
}

impl<'a> Parser<'a> for PromParser<'a> {
    fn next_entry(&mut self) -> Result<Option<Entry>, ParseError> {
        loop {
            self.line_start = self.lexer.pos;
            self.name = None;
            self.labels.clear();
            let entry = match self.next_token() {
                Token::Eof => return Ok(None),
                Token::Linebreak => continue,
                kind @ (Token::Help | Token::Type) => self.parse_metadata(kind),
                Token::Comment => self.parse_comment(),
                first @ (Token::BraceOpen | Token::MName) => self.parse_series(first),
                _ => Err(self.unexpected("expected a valid start token")),
            };
            return entry.map(Some);
        }
    }

    fn help(&self) -> (&'a [u8], Cow<'a, [u8]>) {
        (self.metric_name(), unescape(self.text, false))
    }

    fn metric_type(&self) -> (&'a [u8], MetricType) {
        (self.metric_name(), self.last_type)
    }

    fn comment(&self) -> &'a [u8] {
        self.text
    }

    fn series(&self) -> (&'a [u8], Option<i64>, f64) {
        (self.series, self.timestamp, self.value)
    }

    fn labels(&self, buf: &mut LabelsBuffer<'a>) {
        buf.clear();
        // next_entry() already checked that a series name is UTF-8.
        let name = std::str::from_utf8(self.metric_name()).unwrap_or_default();
        buf.push(Cow::Borrowed(METRIC_NAME_LABEL), unescape_label(name));
        for &(name, value) in &self.labels {
            let name = unescape_label(name);
            let value = normalize_float_label(self.last_type, &name, unescape_label(value));
            buf.push(name, value);
        }
        buf.sort();
    }
}

/// Go's `normalizeFloatsInLabelValues`: `le` on histograms and `quantile` on summaries
/// use OpenMetrics float formatting. Keeps `value` borrowed when it is already canonical.
fn normalize_float_label<'v>(
    metric_type: MetricType,
    name: &str,
    value: Cow<'v, str>,
) -> Cow<'v, str> {
    let is_float_label = match metric_type {
        MetricType::Histogram => name == BUCKET_LABEL,
        MetricType::Summary => name == QUANTILE_LABEL,
        _ => false,
    };
    // NOTE: Go's ParseFloat also accepts hex floats here (le="0x1p3"); we leave them as is.
    let Some(parsed) = is_float_label.then(|| parse_go_float(&value)).flatten() else {
        return value;
    };
    if let Some(common) = common_openmetrics_float(parsed) {
        return Cow::Borrowed(common);
    }
    let mut formatted = FloatBuf::default();
    if format_openmetrics_float(parsed, &mut formatted).is_err() || formatted.as_str() == value {
        return value;
    }
    Cow::Owned(formatted.as_str().to_owned())
}

/// Maps a `# TYPE` value to a [`MetricType`]. Prometheus text spells the unknown type `untyped`.
fn parse_metric_type(text: &[u8]) -> Result<MetricType, ParseError> {
    if text == b"untyped" {
        return Ok(MetricType::Unknown);
    }
    [
        MetricType::Counter,
        MetricType::Gauge,
        MetricType::Histogram,
        MetricType::Summary,
    ]
    .into_iter()
    .find(|metric_type| metric_type.as_str().as_bytes() == text)
    .ok_or_else(|| ParseError::InvalidMetricType(String::from_utf8_lossy(text).into_owned()))
}

/// Go's `strings.Replacer` for `\\` and `\n`, plus `\"` when `quote` is set.
fn unescape(raw: &[u8], quote: bool) -> Cow<'_, [u8]> {
    if !raw.contains(&b'\\') {
        return Cow::Borrowed(raw);
    }
    let mut out = Vec::with_capacity(raw.len());
    let mut bytes = raw.iter().copied().peekable();
    while let Some(byte) = bytes.next() {
        let replaced = match (byte, bytes.peek()) {
            (b'\\', Some(b'\\')) => b'\\',
            (b'\\', Some(b'n')) => b'\n',
            (b'\\', Some(b'"')) if quote => b'"',
            _ => {
                out.push(byte);
                continue;
            }
        };
        bytes.next();
        out.push(replaced);
    }
    Cow::Owned(out)
}

fn unescape_label(raw: &str) -> Cow<'_, str> {
    match unescape(raw.as_bytes(), true) {
        Cow::Borrowed(_) => Cow::Borrowed(raw),
        // Replacing ASCII escapes keeps valid UTF-8 valid, so nothing is lost here.
        Cow::Owned(bytes) => Cow::Owned(
            String::from_utf8(bytes)
                .unwrap_or_else(|error| String::from_utf8_lossy(error.as_bytes()).into_owned()),
        ),
    }
}

/// Go's `parseFloat` in promparse.go, which rejects `pP_` before `strconv.ParseFloat`.
fn parse_sample_value(raw: &[u8]) -> Option<f64> {
    if raw.iter().any(|byte| matches!(byte, b'p' | b'P' | b'_')) {
        return None;
    }
    parse_go_float(std::str::from_utf8(raw).ok()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, PartialEq)]
    enum Got {
        Help(String, String),
        Type(String, MetricType),
        Comment(String),
        Series(String, Option<i64>, u64, Vec<(String, String)>),
    }

    fn parse(input: &[u8]) -> Result<Vec<Got>, ParseError> {
        let mut parser = PromParser::new(input);
        let mut buf = LabelsBuffer::new();
        let mut out = Vec::new();
        let lossy = |bytes: &[u8]| String::from_utf8_lossy(bytes).into_owned();
        while let Some(entry) = parser.next_entry()? {
            out.push(match entry {
                Entry::Help => {
                    let (name, text) = parser.help();
                    Got::Help(lossy(name), lossy(&text))
                }
                Entry::Type => {
                    let (name, mtype) = parser.metric_type();
                    Got::Type(lossy(name), mtype)
                }
                Entry::Comment => Got::Comment(lossy(parser.comment())),
                _ => {
                    let (series, ts, val) = parser.series();
                    parser.labels(&mut buf);
                    let labels = buf
                        .iter()
                        .map(|(name, value)| (name.to_owned(), value.to_owned()))
                        .collect();
                    Got::Series(lossy(series), ts, val.to_bits(), labels)
                }
            });
        }
        Ok(out)
    }

    fn series(raw: &str, ts: Option<i64>, val: f64, labels: &[(&str, &str)]) -> Got {
        let labels = labels
            .iter()
            .map(|(name, value)| (name.to_string(), value.to_string()))
            .collect();
        Got::Series(raw.to_owned(), ts, val.to_bits(), labels)
    }

    fn help(name: &str, text: &str) -> Got {
        Got::Help(name.to_owned(), text.to_owned())
    }

    #[test]
    fn parses_upstream_edge_cases() {
        let input = concat!(
            "# \tTYPE s summary\n",
            "s{quantile=\"0\"} 1\n",
            "s{ quantile = \"1\" a = \"b\", } 2 \t123\n",
            "# Hrandom\n",
            "#\n",
            "# HELP nohelp1\n",
            "# HELP nohelp2 \n",
            "# HELP h  two\\\\ \\n \\\" x\n",
            "# TYPE h histogram\n",
            "h{le=\"10\",l=\"a\\\"\\\\\\n\\x\"}\t-Inf\n",
            "h{le=\"1e6\"} NaN\n",
            "h{le=\"bogus\"} 1\n",
            "# TYPE u untyped\n",
            "u{quantile=\"0\"} +Inf",
        );
        let nan = f64::from_bits(NORMAL_NAN);
        let want = vec![
            Got::Type("s".into(), MetricType::Summary),
            series(
                "s{quantile=\"0\"}",
                None,
                1.0,
                &[("__name__", "s"), ("quantile", "0.0")],
            ),
            series(
                "s{ quantile = \"1\" a = \"b\", }",
                Some(123),
                2.0,
                &[("__name__", "s"), ("a", "b"), ("quantile", "1.0")],
            ),
            Got::Comment("# Hrandom".into()),
            Got::Comment("#".into()),
            help("nohelp1", ""),
            help("nohelp2", ""),
            help("h", " two\\ \n \\\" x"),
            Got::Type("h".into(), MetricType::Histogram),
            series(
                "h{le=\"10\",l=\"a\\\"\\\\\\n\\x\"}",
                None,
                f64::NEG_INFINITY,
                &[("__name__", "h"), ("l", "a\"\\\n\\x"), ("le", "10.0")],
            ),
            series(
                "h{le=\"1e6\"}",
                None,
                nan,
                &[("__name__", "h"), ("le", "1e+06")],
            ),
            series(
                "h{le=\"bogus\"}",
                None,
                1.0,
                &[("__name__", "h"), ("le", "bogus")],
            ),
            Got::Type("u".into(), MetricType::Unknown),
            series(
                "u{quantile=\"0\"}",
                None,
                f64::INFINITY,
                &[("__name__", "u"), ("quantile", "0")],
            ),
        ];
        assert_eq!(parse(input.as_bytes()).unwrap(), want);
    }

    #[test]
    fn parses_quoted_utf8_names_and_null_bytes() {
        let input = concat!(
            "# HELP \"go.gc\" doc\n",
            "{\"go.gc\",quantile=\"0.25\",} 7\n",
            "{\"go.gc\"} 8\n",
            "{ \"a\\\"b\\\\c\\nd\", \"strange©\\n\"=\"6\" } 10.0\n",
            "# HELP metric foo\0bar\n",
            "# c\0mment\n",
            "null_byte_metric{a=\"abc\0\"} 1\n",
            "\0this is EOF\n",
        );
        let want = vec![
            help("go.gc", "doc"),
            series(
                "{\"go.gc\",quantile=\"0.25\",}",
                None,
                7.0,
                &[("__name__", "go.gc"), ("quantile", "0.25")],
            ),
            series("{\"go.gc\"}", None, 8.0, &[("__name__", "go.gc")]),
            series(
                "{ \"a\\\"b\\\\c\\nd\", \"strange©\\n\"=\"6\" }",
                None,
                10.0,
                &[("__name__", "a\"b\\c\nd"), ("strange©\n", "6")],
            ),
            help("metric", "foo\0bar"),
            Got::Comment("# c\0mment".into()),
            series(
                "null_byte_metric{a=\"abc\0\"}",
                None,
                1.0,
                &[("__name__", "null_byte_metric"), ("a", "abc\0")],
            ),
        ];
        assert_eq!(parse(input.as_bytes()).unwrap(), want);
    }

    #[test]
    fn rejects_upstream_error_cases() {
        let inputs: &[&[u8]] = &[
            b"a",
            b"a{b='c'} 1\n",
            b"a{b=\n",
            b"a{\xff=\"foo\"} 1\n",
            b"a{b=\"\xff\"} 1\n",
            b"{\"a\", \"b = \"c\"}",
            b"{\"a\",b\\nc=\"d\"} 1",
            b"a true\n",
            b"something_weird{problem=\"",
            b"empty_label_name{=\"\"} 0",
            b"{A}0",
            b"foo 1_2\n",
            b"foo 0x1p-3\n",
            b"foo 0x1P-3\n",
            b"foo 0 1_2\n",
            b"{a=\"ok\"} 1",
            b"a{\"b\"} 1",
            b"{\"a\",\"b\"} 1",
            b"# TYPE #\n#EOF\n",
            b"# HELP #\n#EOF\n",
            b"# TYPE a bogus\n",
            b"# HELP a \xff\n",
            b"a 1 99999999999999999999\n",
            b"a 1e400\n",
            b"a{b=\0\"ssss\"} 1\n",
            b"a{b=\"\0",
            b"a{b\0=\"hiih\"}\t1",
            b"a\0{b=\"ddd\"} 1",
            b"a 0 1\0",
        ];
        assert!(PromParser::new(b"{\"\xff\"} 1\n").next_entry().is_err());
        for input in inputs {
            assert!(
                parse(input).is_err(),
                "{:?}",
                String::from_utf8_lossy(input)
            );
        }
    }

    #[test]
    fn sample_value_rejects_underscores() {
        assert_eq!(parse_sample_value(b"1_000"), None);
    }

    #[test]
    fn borrowed_labels_outlive_clear() {
        let input = b"# TYPE h histogram\nh{le=\"2\"} 1\n";
        let mut parser = PromParser::new(input);
        let mut buf = LabelsBuffer::new();
        parser.next_entry().unwrap();
        parser.next_entry().unwrap();
        parser.labels(&mut buf);
        let mut kept = Vec::new();
        for (name, value) in buf.as_slice() {
            if let Cow::Borrowed(name) = name {
                kept.push(*name);
            }
            assert_eq!(matches!(value, Cow::Owned(_)), name == BUCKET_LABEL);
        }
        buf.clear();
        assert_eq!(kept, [METRIC_NAME_LABEL, BUCKET_LABEL]);
    }

    #[test]
    fn common_float_labels_do_not_allocate() {
        let cases = [
            (MetricType::Summary, QUANTILE_LABEL, "0", "0.0"),
            (MetricType::Summary, QUANTILE_LABEL, "1", "1.0"),
            (MetricType::Histogram, BUCKET_LABEL, "1", "1.0"),
            (MetricType::Histogram, BUCKET_LABEL, "-1", "-1.0"),
            (MetricType::Histogram, BUCKET_LABEL, "+Inf", "+Inf"),
            (MetricType::Summary, QUANTILE_LABEL, "nan", "NaN"),
        ];
        for (metric_type, name, raw, want) in cases {
            let normalized = normalize_float_label(metric_type, name, Cow::Borrowed(raw));
            assert!(
                matches!(normalized, Cow::Borrowed(text) if text == want),
                "{raw}"
            );
        }
    }
}
