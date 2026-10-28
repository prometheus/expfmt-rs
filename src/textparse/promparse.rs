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
//! [`promparse.go`](https://github.com/prometheus/prometheus/blob/main/model/textparse/promparse.go)
//! and its lexer [`promlex.l`](https://github.com/prometheus/prometheus/blob/main/model/textparse/promlex.l).

use std::borrow::Cow;
use std::fmt::{self, Write};

use super::{Entry, LabelsBuffer, METRIC_NAME_LABEL, MetricType, ParseError, Parser};

/// Go's `value.NormalNaN`, the canonical NaN bit pattern Prometheus stores.
const NORMAL_NAN: u64 = 0x7ff8_0000_0000_0001;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    Init,
    Comment,
    Meta1,
    Meta2,
    Labels,
    LValue,
    Value,
    Timestamp,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Token {
    Invalid,
    Eof,
    Linebreak,
    Whitespace,
    Help,
    Type,
    Text,
    Comment,
    MName,
    QString,
    BraceOpen,
    BraceClose,
    LName,
    LValue,
    Comma,
    Equal,
    Timestamp,
    Value,
}

fn is_ws(byte: u8) -> bool {
    byte == b' ' || byte == b'\t'
}

fn is_name_start(byte: u8) -> bool {
    byte.is_ascii_alphabetic() || byte == b'_' || byte == b':'
}

fn is_label_start(byte: u8) -> bool {
    byte.is_ascii_alphabetic() || byte == b'_'
}

/// Hand-written port of the `promlex.l` rules. The input behaves as if a `\n`
/// were appended, like Go's `append(b, '\n')`, without copying it.
struct Lexer<'a> {
    input: &'a [u8],
    i: usize,
    start: usize,
    state: State,
}

impl<'a> Lexer<'a> {
    fn len(&self) -> usize {
        self.input.len() + 1
    }

    fn byte(&self, index: usize) -> u8 {
        match self.input.get(index) {
            Some(&byte) => byte,
            None if index == self.input.len() => b'\n',
            None => 0,
        }
    }

    fn cur(&self) -> u8 {
        self.byte(self.i)
    }

    fn buf(&self) -> &'a [u8] {
        let end = self.input.len();
        &self.input[self.start.min(end)..self.i.min(end)]
    }

    // Go's lexer skips NUL bytes inside label values, help text and comments,
    // and returns 0 (EOF) past the end of the input.
    fn next(&mut self) -> u8 {
        self.i += 1;
        if self.i >= self.len() {
            return 0;
        }
        while self.byte(self.i) == 0
            && matches!(self.state, State::LValue | State::Meta2 | State::Comment)
        {
            self.i += 1;
        }
        self.byte(self.i)
    }

    fn eat_while(&mut self, mut byte: u8, pred: impl Fn(u8) -> bool) -> u8 {
        while pred(byte) {
            byte = self.next();
        }
        byte
    }

    /// Consumes `"(\\.|[^\\"])*"` starting at the opening quote.
    fn quoted(&mut self) -> bool {
        loop {
            match self.next() {
                b'"' => {
                    self.next();
                    return true;
                }
                b'\\' => {
                    if matches!(self.next(), 0 | b'\n') {
                        return false;
                    }
                }
                0 => return false,
                _ => {}
            }
        }
    }

    fn consume_comment(&mut self) -> Token {
        let mut byte = self.cur();
        loop {
            match byte {
                0 => return Token::Eof,
                b'\n' => {
                    self.state = State::Init;
                    return Token::Comment;
                }
                _ => byte = self.next(),
            }
        }
    }

    fn whitespace(&mut self) -> Token {
        let next = self.next();
        self.eat_while(next, is_ws);
        Token::Whitespace
    }

    fn lex(&mut self) -> Token {
        if self.i >= self.len() {
            return Token::Eof;
        }
        let mut byte = self.cur();
        self.start = self.i;
        loop {
            return match self.state {
                State::Init => match byte {
                    0 => Token::Eof,
                    b'\n' => {
                        self.next();
                        Token::Linebreak
                    }
                    b' ' | b'\t' => self.whitespace(),
                    b'#' => {
                        let next = self.next();
                        if !is_ws(next) {
                            return self.consume_comment();
                        }
                        let next = self.next();
                        byte = self.eat_while(next, is_ws);
                        self.state = State::Comment;
                        continue;
                    }
                    b'{' => {
                        self.next();
                        self.state = State::Labels;
                        Token::BraceOpen
                    }
                    _ if is_name_start(byte) => {
                        let next = self.next();
                        self.eat_while(next, |next_byte| {
                            is_name_start(next_byte) || next_byte.is_ascii_digit()
                        });
                        self.state = State::Value;
                        Token::MName
                    }
                    _ => Token::Invalid,
                },
                State::Comment => match byte {
                    b'H' | b'T' => {
                        let (rest, token) = if byte == b'H' {
                            (b"ELP", Token::Help)
                        } else {
                            (b"YPE", Token::Type)
                        };
                        if rest.iter().all(|&expected| self.next() == expected)
                            && is_ws(self.next())
                        {
                            self.whitespace();
                            self.state = State::Meta1;
                            return token;
                        }
                        self.consume_comment()
                    }
                    b' ' | b'\t' => self.whitespace(),
                    _ => self.consume_comment(),
                },
                State::Meta1 => match byte {
                    b'"' => {
                        if !self.quoted() {
                            return Token::Invalid;
                        }
                        self.state = State::Meta2;
                        Token::MName
                    }
                    b' ' | b'\t' => self.whitespace(),
                    _ if is_name_start(byte) => {
                        let next = self.next();
                        self.eat_while(next, |next_byte| {
                            is_name_start(next_byte) || next_byte.is_ascii_digit()
                        });
                        self.state = State::Meta2;
                        Token::MName
                    }
                    _ => Token::Invalid,
                },
                State::Meta2 => {
                    // `[ \t]+` wins over `[^\n]*` on a tie, so trailing blanks are whitespace.
                    if is_ws(byte) {
                        let next = self.next();
                        byte = self.eat_while(next, is_ws);
                        if byte == 0 || byte == b'\n' {
                            return Token::Whitespace;
                        }
                    }
                    self.eat_while(byte, |next_byte| next_byte != 0 && next_byte != b'\n');
                    self.state = State::Init;
                    Token::Text
                }
                State::Labels => match byte {
                    b'"' => {
                        if !self.quoted() {
                            return Token::Invalid;
                        }
                        Token::QString
                    }
                    b',' => {
                        self.next();
                        Token::Comma
                    }
                    b'=' => {
                        self.next();
                        self.state = State::LValue;
                        Token::Equal
                    }
                    b'}' => {
                        self.next();
                        self.state = State::Value;
                        Token::BraceClose
                    }
                    b' ' | b'\t' => self.whitespace(),
                    _ if is_label_start(byte) => {
                        let next = self.next();
                        self.eat_while(next, |next_byte| {
                            is_label_start(next_byte) || next_byte.is_ascii_digit()
                        });
                        Token::LName
                    }
                    _ => Token::Invalid,
                },
                State::LValue => match byte {
                    b'"' => {
                        if !self.quoted() {
                            return Token::Invalid;
                        }
                        self.state = State::Labels;
                        Token::LValue
                    }
                    b' ' | b'\t' => self.whitespace(),
                    _ => Token::Invalid,
                },
                State::Value => match byte {
                    b' ' | b'\t' => self.whitespace(),
                    b'{' => {
                        self.next();
                        self.state = State::Labels;
                        Token::BraceOpen
                    }
                    0 | b'\n' => Token::Invalid,
                    _ => {
                        let next = self.next();
                        self.eat_while(next, |next_byte| {
                            !matches!(next_byte, 0 | b'\n' | b' ' | b'\t' | b'{')
                        });
                        self.state = State::Timestamp;
                        Token::Value
                    }
                },
                State::Timestamp => match byte {
                    b'\n' => {
                        self.next();
                        self.state = State::Init;
                        Token::Linebreak
                    }
                    b' ' | b'\t' => self.whitespace(),
                    b'0'..=b'9' => {
                        let next = self.next();
                        self.eat_while(next, |next_byte| next_byte.is_ascii_digit());
                        Token::Timestamp
                    }
                    _ => Token::Invalid,
                },
            };
        }
    }
}

/// Zero-copy parser for the Prometheus text exposition format 0.0.4.
///
/// Mirrors Go's `textparse.NewPromParser` with type and unit labels disabled.
pub struct PromParser<'a> {
    lexer: Lexer<'a>,
    series: &'a [u8],
    text: &'a [u8],
    mtype: MetricType,
    val: f64,
    ts: Option<i64>,
    start: usize,
    name: Option<(usize, usize)>,
    labels: Vec<[usize; 4]>,
}

impl<'a> PromParser<'a> {
    /// Creates a parser over `input`.
    pub fn new(input: &'a [u8]) -> Self {
        Self {
            lexer: Lexer {
                input,
                i: 0,
                start: 0,
                state: State::Init,
            },
            series: b"",
            text: b"",
            mtype: MetricType::Unknown,
            val: 0.0,
            ts: None,
            start: 0,
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
            offset: self.lexer.start,
        }
    }

    fn parse_metadata(&mut self, kind: Token) -> Result<Entry, ParseError> {
        if self.next_token() != Token::MName {
            return Err(self.unexpected("expected metric name"));
        }
        let (mut start, mut end) = (self.lexer.start, self.lexer.i);
        if self.lexer.input[start] == b'"' && self.lexer.input[end - 1] == b'"' {
            start += 1;
            end -= 1;
        }
        self.name = Some((start, end));
        if self.next_token() != Token::Text {
            return Err(self.unexpected("expected text"));
        }
        let text = self.lexer.buf();
        self.text = text.get(1..).unwrap_or_default();
        let entry = if kind == Token::Type {
            self.mtype = match self.text {
                b"counter" => MetricType::Counter,
                b"gauge" => MetricType::Gauge,
                b"histogram" => MetricType::Histogram,
                b"summary" => MetricType::Summary,
                b"untyped" => MetricType::Unknown,
                other => {
                    return Err(ParseError::InvalidMetricType(
                        String::from_utf8_lossy(other).into_owned(),
                    ));
                }
            };
            Entry::Type
        } else {
            if std::str::from_utf8(self.text).is_err() {
                return Err(ParseError::InvalidUtf8 {
                    offset: self.lexer.start,
                });
            }
            Entry::Help
        };
        if self.next_token() != Token::Linebreak {
            return Err(self.unexpected("expected linebreak after metadata"));
        }
        Ok(entry)
    }

    fn parse_label_values(&mut self) -> Result<(), ParseError> {
        let mut token = self.next_token();
        loop {
            let (mut name_start, mut name_end) = (self.lexer.start, self.lexer.i);
            let quoted = match token {
                Token::BraceClose => return Ok(()),
                Token::LName => false,
                Token::QString => true,
                _ => return Err(self.unexpected("expected label name")),
            };
            if quoted && std::str::from_utf8(self.lexer.buf()).is_err() {
                return Err(ParseError::InvalidUtf8 { offset: name_start });
            }
            token = self.next_token();
            if quoted && matches!(token, Token::Comma | Token::BraceClose) {
                if self.name.is_some() {
                    return Err(ParseError::InvalidMetricName { offset: self.start });
                }
                self.name = Some((name_start + 1, name_end - 1));
                if token == Token::BraceClose {
                    return Ok(());
                }
                token = self.next_token();
                continue;
            }
            if quoted {
                name_start += 1;
                name_end -= 1;
            }
            if token != Token::Equal {
                return Err(self.unexpected("expected equal"));
            }
            if self.next_token() != Token::LValue {
                return Err(self.unexpected("expected label value"));
            }
            if std::str::from_utf8(self.lexer.buf()).is_err() {
                return Err(ParseError::InvalidUtf8 {
                    offset: self.lexer.start,
                });
            }
            self.labels
                .push([name_start, name_end, self.lexer.start + 1, self.lexer.i - 1]);
            token = self.next_token();
            if token == Token::Comma {
                token = self.next_token();
            }
        }
    }

    fn parse_metric_suffix(&mut self, token: Token) -> Result<Entry, ParseError> {
        if self.name.is_none() {
            return Err(ParseError::InvalidMetricName { offset: self.start });
        }
        if token != Token::Value {
            return Err(self.unexpected("expected value after metric"));
        }
        let raw = self.lexer.buf();
        let val = parse_sample_value(raw)
            .ok_or_else(|| ParseError::InvalidValue(String::from_utf8_lossy(raw).into_owned()))?;
        self.val = if val.is_nan() {
            f64::from_bits(NORMAL_NAN)
        } else {
            val
        };
        self.ts = None;
        match self.next_token() {
            Token::Linebreak => {}
            Token::Timestamp => {
                let raw = self.lexer.buf();
                let ts = std::str::from_utf8(raw)
                    .ok()
                    .and_then(|digits| digits.parse().ok())
                    .ok_or_else(|| {
                        ParseError::InvalidTimestamp(String::from_utf8_lossy(raw).into_owned())
                    })?;
                self.ts = Some(ts);
                if self.next_token() != Token::Linebreak {
                    return Err(self.unexpected("expected linebreak after timestamp"));
                }
            }
            _ => return Err(self.unexpected("expected timestamp or linebreak")),
        }
        Ok(Entry::Series)
    }

    fn label_str(&self, start: usize, end: usize, quote: bool) -> Result<Cow<'a, str>, ParseError> {
        let invalid = ParseError::InvalidUtf8 { offset: start };
        Ok(match unescape(&self.lexer.input[start..end], quote) {
            Cow::Borrowed(raw) => Cow::Borrowed(std::str::from_utf8(raw).map_err(|_| invalid)?),
            Cow::Owned(raw) => Cow::Owned(String::from_utf8(raw).map_err(|_| invalid)?),
        })
    }
}

impl<'a> Parser<'a> for PromParser<'a> {
    fn next_entry(&mut self) -> Result<Option<Entry>, ParseError> {
        loop {
            self.start = self.lexer.i;
            self.name = None;
            self.labels.clear();
            let entry = match self.next_token() {
                Token::Eof => return Ok(None),
                Token::Linebreak => continue,
                kind @ (Token::Help | Token::Type) => self.parse_metadata(kind),
                Token::Comment => {
                    self.text = self.lexer.buf();
                    if self.next_token() != Token::Linebreak {
                        return Err(self.unexpected("expected linebreak after comment"));
                    }
                    Ok(Entry::Comment)
                }
                Token::BraceOpen => {
                    self.parse_label_values()?;
                    self.series = &self.lexer.input[self.start..self.lexer.i];
                    let token = self.next_token();
                    self.parse_metric_suffix(token)
                }
                Token::MName => {
                    // Go uses the line start, so leading blanks become part of the name.
                    self.name = Some((self.start, self.lexer.i));
                    self.series = &self.lexer.input[self.start..self.lexer.i];
                    let mut token = self.next_token();
                    if token == Token::BraceOpen {
                        self.parse_label_values()?;
                        self.series = &self.lexer.input[self.start..self.lexer.i];
                        token = self.next_token();
                    }
                    self.parse_metric_suffix(token)
                }
                _ => Err(self.unexpected("expected a valid start token")),
            };
            return entry.map(Some);
        }
    }

    fn help(&self) -> (&'a [u8], Cow<'a, [u8]>) {
        (self.metric_name(), unescape(self.text, false))
    }

    fn metric_type(&self) -> (&'a [u8], MetricType) {
        (self.metric_name(), self.mtype)
    }

    fn comment(&self) -> &'a [u8] {
        self.text
    }

    fn series(&self) -> (&'a [u8], Option<i64>, f64) {
        (self.series, self.ts, self.val)
    }

    fn labels(&self, buf: &mut LabelsBuffer<'a>) -> Result<(), ParseError> {
        buf.clear();
        let (start, end) = self.name.unwrap_or_default();
        buf.push(
            Cow::Borrowed(METRIC_NAME_LABEL),
            self.label_str(start, end, true)?,
        );
        for &[name_start, name_end, value_start, value_end] in &self.labels {
            let name = self.label_str(name_start, name_end, true)?;
            let mut value = self.label_str(value_start, value_end, true)?;
            let normalize = match self.mtype {
                MetricType::Histogram => name == "le",
                MetricType::Summary => name == "quantile",
                _ => false,
            };
            // ponytail: Go's ParseFloat also accepts hex floats here (le="0x1p3"); we leave them as is.
            if let Some(parsed) = normalize
                .then(|| parse_go_float(value.as_bytes()))
                .flatten()
            {
                let mut formatted = FloatBuf::default();
                if format_openmetrics_float(parsed, &mut formatted).is_ok()
                    && formatted.as_str() != value
                {
                    value = Cow::Owned(formatted.as_str().to_owned());
                }
            }
            buf.push(name, value);
        }
        buf.sort();
        Ok(())
    }
}

impl<'a> PromParser<'a> {
    fn metric_name(&self) -> &'a [u8] {
        let (start, end) = self.name.unwrap_or_default();
        &self.lexer.input[start..end]
    }
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

/// Go's `parseFloat` in promparse.go, which rejects `pP_` before `strconv.ParseFloat`.
fn parse_sample_value(raw: &[u8]) -> Option<f64> {
    if raw.iter().any(|byte| matches!(byte, b'p' | b'P' | b'_')) {
        return None;
    }
    parse_go_float(raw)
}

/// Go's `strconv.ParseFloat(s, 64)`, without hex float support.
fn parse_go_float(raw: &[u8]) -> Option<f64> {
    let text = std::str::from_utf8(raw).ok()?;
    if text.contains('_') {
        return underscores_ok(raw)
            .then(|| parse_go_float(text.replace('_', "").as_bytes()))
            .flatten();
    }
    let unsigned = text.strip_prefix(['+', '-']).unwrap_or(text);
    let special = unsigned.starts_with(|c: char| c.is_ascii_alphabetic());
    let val: f64 = text.parse().ok()?;
    // Go rejects a signed NaN, and reports overflow to infinity as an error.
    let signed_nan = val.is_nan() && unsigned.len() != text.len();
    let overflow = val.is_infinite() && !special;
    (!signed_nan && !overflow).then_some(val)
}

/// Go accepts `_` only between digits, like `1_000`.
fn underscores_ok(raw: &[u8]) -> bool {
    raw.iter().enumerate().all(|(index, &byte)| {
        byte != b'_'
            || (index > 0
                && raw[index - 1].is_ascii_digit()
                && raw.get(index + 1).is_some_and(u8::is_ascii_digit))
    })
}

/// Fixed-size buffer so float formatting in `labels()` does not allocate.
#[derive(Default)]
struct FloatBuf {
    bytes: [u8; 32],
    len: usize,
}

impl FloatBuf {
    fn as_str(&self) -> &str {
        std::str::from_utf8(&self.bytes[..self.len]).unwrap_or_default()
    }
}

impl fmt::Write for FloatBuf {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        let end = self.len + text.len();
        self.bytes
            .get_mut(self.len..end)
            .ok_or(fmt::Error)?
            .copy_from_slice(text.as_bytes());
        self.len = end;
        Ok(())
    }
}

/// Go's `labels.FormatOpenMetricsFloat`: `strconv.FormatFloat(v, 'g', -1, 64)` plus `.0`.
fn format_openmetrics_float(val: f64, out: &mut FloatBuf) -> fmt::Result {
    match val {
        0.0 => return out.write_str("0.0"),
        _ if val.is_nan() => return out.write_str("NaN"),
        f64::INFINITY => return out.write_str("+Inf"),
        f64::NEG_INFINITY => return out.write_str("-Inf"),
        _ => {}
    }
    let mut scientific = FloatBuf::default();
    write!(scientific, "{val:e}")?;
    // Go picks the correctly rounded digits among the shortest forms, Rust may not,
    // so keep Rust's shortest digit count and round again to it.
    let mantissa_digits = scientific.as_str().split('e').next().unwrap_or_default();
    let precision = mantissa_digits.bytes().filter(u8::is_ascii_digit).count() - 1;
    scientific = FloatBuf::default();
    write!(scientific, "{val:.precision$e}")?;
    let (mantissa, exp) = scientific.as_str().split_once('e').ok_or(fmt::Error)?;
    let exp: i32 = exp.parse().map_err(|_| fmt::Error)?;
    let (sign, mantissa) = match mantissa.strip_prefix('-') {
        Some(rest) => ("-", rest),
        None => ("", mantissa),
    };
    out.write_str(sign)?;
    // Shortest 'g' switches to exponent form when exp < -4 || exp >= 6.
    if !(-4..6).contains(&exp) {
        let exp_sign = if exp < 0 { '-' } else { '+' };
        return write!(out, "{mantissa}e{exp_sign}{:02}", exp.abs());
    }
    let mut digits = mantissa.bytes().filter(|byte| *byte != b'.');
    if exp < 0 {
        out.write_str("0.")?;
        for _ in exp + 1..0 {
            out.write_str("0")?;
        }
        return digits.try_for_each(|digit| out.write_char(char::from(digit)));
    }
    let integer_len = exp as usize + 1;
    let digit_count = mantissa.len() - usize::from(mantissa.contains('.'));
    for (index, digit) in digits.enumerate() {
        if index == integer_len {
            out.write_str(".")?;
        }
        out.write_char(char::from(digit))?;
    }
    for _ in digit_count..integer_len {
        out.write_str("0")?;
    }
    if digit_count <= integer_len {
        out.write_str(".0")?;
    }
    Ok(())
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
                    parser.labels(&mut buf)?;
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
    fn parse_go_float_matches_go() {
        assert_eq!(parse_sample_value(b"1_000"), None);
        let ok = [
            ("1", 1.0),
            ("+.5", 0.5),
            ("5.", 5.0),
            ("1E+5", 1e5),
            ("+Inf", f64::INFINITY),
            ("-inf", f64::NEG_INFINITY),
            ("+Infinity", f64::INFINITY),
            ("1e-400", 0.0),
            ("00012", 12.0),
            ("1_000", 1000.0),
            ("1e1_0", 1e10),
        ];
        for (text, want) in ok {
            assert_eq!(parse_go_float(text.as_bytes()), Some(want), "{text}");
        }
        assert!(parse_go_float(b"nan").unwrap().is_nan());
        for text in [
            ".", "1e", "infin", "+NaN", "-nan", "1e400", "0x10", "+", "e5", "1__0", "_1", "1_",
        ] {
            assert_eq!(parse_go_float(text.as_bytes()), None, "{text}");
        }
    }

    #[test]
    fn format_openmetrics_float_matches_go() {
        let cases = [
            (1.0, "1.0"),
            (-0.0, "0.0"),
            (0.5, "0.5"),
            (123456.0, "123456.0"),
            (1e6, "1e+06"),
            (1234567.5, "1.2345675e+06"),
            (0.0001, "0.0001"),
            (1e-5, "1e-05"),
            (1e21, "1e+21"),
            (5e-324, "5e-324"),
            (-0.00012, "-0.00012"),
            (12.5, "12.5"),
            (1453167548838524.2, "1.4531675488385242e+15"),
            (1234.5678901234567, "1234.5678901234567"),
            (f64::NEG_INFINITY, "-Inf"),
        ];
        for (val, want) in cases {
            let mut out = FloatBuf::default();
            format_openmetrics_float(val, &mut out).unwrap();
            assert_eq!(out.as_str(), want);
        }
    }
}
