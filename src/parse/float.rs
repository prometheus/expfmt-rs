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

//! Go-compatible float parsing and OpenMetrics float formatting, shared by the text parsers.

use std::borrow::Cow;
use std::fmt::{self, Write};

/// Go's `strconv.ParseFloat(s, 64)`, without hex float support.
pub(super) fn parse_go_float(text: &str) -> Option<f64> {
    let text = if text.contains('_') {
        if !underscores_ok(text.as_bytes()) {
            return None;
        }
        Cow::Owned(text.replace('_', ""))
    } else {
        Cow::Borrowed(text)
    };
    let unsigned = text.strip_prefix(['+', '-']).unwrap_or(&text);
    if unsigned.eq_ignore_ascii_case("inf") || unsigned.eq_ignore_ascii_case("infinity") {
        return Some(if text.starts_with('-') {
            f64::NEG_INFINITY
        } else {
            f64::INFINITY
        });
    }
    // Go rejects a signed NaN, and reports overflow to infinity as an error.
    if unsigned.eq_ignore_ascii_case("nan") {
        return (unsigned.len() == text.len()).then_some(f64::NAN);
    }
    text.parse().ok().filter(|value: &f64| value.is_finite())
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
pub(super) struct FloatBuf {
    bytes: [u8; 32],
    len: usize,
}

impl FloatBuf {
    pub(super) fn as_str(&self) -> &str {
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

/// The values Go's `labels.FormatOpenMetricsFloat` returns as constants.
pub(super) fn common_openmetrics_float(value: f64) -> Option<&'static str> {
    match value {
        0.0 => Some("0.0"),
        1.0 => Some("1.0"),
        -1.0 => Some("-1.0"),
        f64::INFINITY => Some("+Inf"),
        f64::NEG_INFINITY => Some("-Inf"),
        _ if value.is_nan() => Some("NaN"),
        _ => None,
    }
}

/// Go's `labels.FormatOpenMetricsFloat`: `strconv.FormatFloat(v, 'g', -1, 64)` plus `.0`.
pub(super) fn format_openmetrics_float(value: f64, out: &mut FloatBuf) -> fmt::Result {
    if let Some(common) = common_openmetrics_float(value) {
        return out.write_str(common);
    }
    let scientific = go_shortest_scientific(value)?;
    let (mantissa, exp) = scientific.as_str().split_once('e').ok_or(fmt::Error)?;
    let exp: i32 = exp.parse().map_err(|_| fmt::Error)?;
    let mantissa = match mantissa.strip_prefix('-') {
        Some(unsigned) => {
            out.write_str("-")?;
            unsigned
        }
        None => mantissa,
    };
    // Shortest 'g' switches to exponent form when exp < -4 || exp >= 6.
    if (-4..6).contains(&exp) {
        write_positional(mantissa, exp, out)?;
    } else {
        let exp_sign = if exp < 0 { '-' } else { '+' };
        write!(out, "{mantissa}e{exp_sign}{:02}", exp.abs())?;
    }
    Ok(())
}

/// Formats `value` like `{:e}` with the digits Go's `strconv.FormatFloat(v, 'e', -1, 64)` picks.
fn go_shortest_scientific(value: f64) -> Result<FloatBuf, fmt::Error> {
    let mut shortest = FloatBuf::default();
    write!(shortest, "{value:e}")?;
    // Go picks the correctly rounded digits among the shortest forms, Rust may not,
    // so keep Rust's shortest digit count and round again to it.
    let mantissa = shortest.as_str().split('e').next().unwrap_or_default();
    let precision = mantissa.bytes().filter(u8::is_ascii_digit).count() - 1;
    let mut rounded = FloatBuf::default();
    write!(rounded, "{value:.precision$e}")?;
    Ok(rounded)
}

/// Writes an unsigned mantissa such as `1.2345` with exponent `exp` as `12345.0` or `0.00012345`.
fn write_positional(mantissa: &str, exp: i32, out: &mut FloatBuf) -> fmt::Result {
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

    #[test]
    fn parse_go_float_matches_go() {
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
            assert_eq!(parse_go_float(text), Some(want), "{text}");
        }
        assert!(parse_go_float("nan").unwrap().is_nan());
        for text in [
            ".", "1e", "infin", "+NaN", "-nan", "1e400", "0x10", "+", "e5", "1__0", "_1", "1_",
        ] {
            assert_eq!(parse_go_float(text), None, "{text}");
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
