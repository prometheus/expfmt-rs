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

//! Prometheus and OpenMetrics `Content-Type` and `Accept` header parsing,
//! format descriptors, and UTF-8 escaping schemes.
//!
//! Mirrors [`prometheus/common/expfmt/expfmt.go`](https://github.com/prometheus/common/blob/main/expfmt/expfmt.go),
//! [`encode.go`](https://github.com/prometheus/common/blob/main/expfmt/encode.go), and
//! [`decode.go`](https://github.com/prometheus/common/blob/main/expfmt/decode.go).

use std::borrow::Cow;
use std::collections::HashMap;
use std::fmt;
use std::str::FromStr;

/// MIME type for Prometheus classic text exposition format.
pub const TEXT_TYPE: &str = "text/plain";

/// Version string for Prometheus classic text format.
pub const TEXT_VERSION: &str = "0.0.4";

/// MIME type for Prometheus protobuf wire format.
pub const PROTO_TYPE: &str = "application/vnd.google.protobuf";

/// Protobuf message type for Prometheus exposition payloads.
pub const PROTO_PROTOCOL: &str = "io.prometheus.client.MetricFamily";

/// Prefix for Prometheus protobuf `Content-Type` headers.
pub const PROTO_FMT: &str =
    "application/vnd.google.protobuf; proto=io.prometheus.client.MetricFamily;";

/// MIME type for OpenMetrics text exposition format.
pub const OPEN_METRICS_TYPE: &str = "application/openmetrics-text";

/// Version string for OpenMetrics 0.0.1.
pub const OPEN_METRICS_VERSION_0_0_1: &str = "0.0.1";

/// Version string for OpenMetrics 1.0.0.
pub const OPEN_METRICS_VERSION_1_0_0: &str = "1.0.0";

/// Version string for OpenMetrics 2.0.0-rc.
pub const OPEN_METRICS_VERSION_2_0_0_RC: &str = "2.0.0-rc";

/// Version string for OpenMetrics 2.0.0.
pub const OPEN_METRICS_VERSION_2_0_0: &str = "2.0.0";

/// Content-Type parameter key specifying the UTF-8 metric and label name escaping scheme.
pub const ESCAPING_KEY: &str = "escaping";

const PROTO_KEY: &str = "proto";
const ENCODING_KEY: &str = "encoding";
const VERSION_KEY: &str = "version";
const CHARSET_KEY: &str = "charset";

const ENCODING_DELIMITED: &str = "delimited";
const ENCODING_TEXT: &str = "text";
const ENCODING_COMPACT_TEXT: &str = "compact-text";
const CHARSET_UTF8: &str = "utf-8";

const ESCAPE_ALLOW_UTF8: &str = "allow-utf-8";
const ESCAPE_UNDERSCORES: &str = "underscores";
const ESCAPE_DOTS: &str = "dots";
const ESCAPE_VALUES: &str = "values";

/// Baseline `Content-Type` string for unknown formats.
pub const FMT_UNKNOWN: &str = "<unknown>";

/// Baseline `Content-Type` string for Prometheus 0.0.4 text format.
pub const FMT_TEXT: &str = "text/plain; version=0.0.4; charset=utf-8";

/// Baseline `Content-Type` string for varint length-delimited Prometheus protobuf format.
pub const FMT_PROTO_DELIM: &str =
    "application/vnd.google.protobuf; proto=io.prometheus.client.MetricFamily; encoding=delimited";

/// Baseline `Content-Type` string for text-encoded Prometheus protobuf format.
pub const FMT_PROTO_TEXT: &str =
    "application/vnd.google.protobuf; proto=io.prometheus.client.MetricFamily; encoding=text";

/// Baseline `Content-Type` string for compact text-encoded Prometheus protobuf format.
pub const FMT_PROTO_COMPACT: &str = "application/vnd.google.protobuf; proto=io.prometheus.client.MetricFamily; encoding=compact-text";

/// Baseline `Content-Type` string for OpenMetrics 2.0.0 text format.
pub const FMT_OPEN_METRICS_2_0_0: &str =
    "application/openmetrics-text; version=2.0.0; charset=utf-8";

/// Baseline `Content-Type` string for OpenMetrics 2.0.0-rc text format.
pub const FMT_OPEN_METRICS_2_0_0_RC: &str =
    "application/openmetrics-text; version=2.0.0-rc; charset=utf-8";

/// Baseline `Content-Type` string for OpenMetrics 1.0.0 text format.
pub const FMT_OPEN_METRICS_1_0_0: &str =
    "application/openmetrics-text; version=1.0.0; charset=utf-8";

/// Baseline `Content-Type` string for OpenMetrics 0.0.1 text format.
pub const FMT_OPEN_METRICS_0_0_1: &str =
    "application/openmetrics-text; version=0.0.1; charset=utf-8";

/// UTF-8 metric and label name escaping scheme negotiated via the `escaping=...` parameter.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum EscapingScheme {
    /// No escaping (`escaping=allow-utf-8`). Full UTF-8 names are allowed (quoted when needed).
    AllowUtf8,
    /// Replace invalid legacy characters with underscores (`escaping=underscores`).
    /// Matches `model.UnderscoreEscaping`, the default `NameEscapingScheme` in `prometheus/common/model`.
    #[default]
    EscapeUnderscores,
    /// Escape dots and other invalid characters (`escaping=dots`).
    EscapeDots,
    /// Prefix and hex-encode invalid characters (`escaping=values`).
    EscapeValues,
}

impl EscapingScheme {
    /// Wire value for `escaping=<scheme>` parameters.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AllowUtf8 => ESCAPE_ALLOW_UTF8,
            Self::EscapeUnderscores => ESCAPE_UNDERSCORES,
            Self::EscapeDots => ESCAPE_DOTS,
            Self::EscapeValues => ESCAPE_VALUES,
        }
    }
}

impl fmt::Display for EscapingScheme {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Error returned when an `escaping=...` parameter does not match a known [`EscapingScheme`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnknownEscapingSchemeError(pub String);

impl fmt::Display for UnknownEscapingSchemeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unknown escaping scheme: {}", self.0)
    }
}

impl std::error::Error for UnknownEscapingSchemeError {}

impl FromStr for EscapingScheme {
    type Err = UnknownEscapingSchemeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            ESCAPE_ALLOW_UTF8 => Ok(Self::AllowUtf8),
            ESCAPE_UNDERSCORES => Ok(Self::EscapeUnderscores),
            ESCAPE_DOTS => Ok(Self::EscapeDots),
            ESCAPE_VALUES => Ok(Self::EscapeValues),
            other => Err(UnknownEscapingSchemeError(other.to_owned())),
        }
    }
}

/// High-level wire format category deduced from a [`Format`] string.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum FormatType {
    /// Unrecognized or invalid format.
    #[default]
    Unknown,
    /// Single-line compact protobuf text (`encoding=compact-text`).
    ProtoCompact,
    /// Varint length-delimited binary protobuf (`encoding=delimited`).
    ProtoDelim,
    /// Multi-line protobuf text (`encoding=text`).
    ProtoText,
    /// Classic Prometheus 0.0.4 text (`text/plain`).
    TextPlain,
    /// OpenMetrics text (`application/openmetrics-text`).
    OpenMetrics,
}

/// Error returned by [`Format::new_open_metrics`] for an unsupported OpenMetrics version string.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnknownOpenMetricsVersionError(pub String);

impl fmt::Display for UnknownOpenMetricsVersionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unknown open metrics version string: {}", self.0)
    }
}

impl std::error::Error for UnknownOpenMetricsVersionError {}

/// HTTP `Content-Type` representation of a Prometheus or OpenMetrics wire protocol.
///
/// Because `Content-Type` values on the wire may include dynamic parameters such as
/// `; escaping=...` or whitespace variations, callers should inspect [`Format::format_type`],
/// [`Format::version`], and [`Format::to_escaping_scheme`] rather than comparing raw strings.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Format(Cow<'static, str>);

impl Format {
    /// Unknown format (`<unknown>`).
    pub const UNKNOWN: Self = Self(Cow::Borrowed(FMT_UNKNOWN));
    /// Prometheus 0.0.4 plain text format.
    pub const TEXT: Self = Self(Cow::Borrowed(FMT_TEXT));
    /// Varint length-delimited binary protobuf format.
    pub const PROTO_DELIM: Self = Self(Cow::Borrowed(FMT_PROTO_DELIM));
    /// Multi-line text protobuf format.
    pub const PROTO_TEXT: Self = Self(Cow::Borrowed(FMT_PROTO_TEXT));
    /// Compact text protobuf format.
    pub const PROTO_COMPACT: Self = Self(Cow::Borrowed(FMT_PROTO_COMPACT));
    /// OpenMetrics 2.0.0 text format.
    pub const OPEN_METRICS_2_0_0: Self = Self(Cow::Borrowed(FMT_OPEN_METRICS_2_0_0));
    /// OpenMetrics 2.0.0-rc text format.
    pub const OPEN_METRICS_2_0_0_RC: Self = Self(Cow::Borrowed(FMT_OPEN_METRICS_2_0_0_RC));
    /// OpenMetrics 1.0.0 text format.
    pub const OPEN_METRICS_1_0_0: Self = Self(Cow::Borrowed(FMT_OPEN_METRICS_1_0_0));
    /// OpenMetrics 0.0.1 text format.
    pub const OPEN_METRICS_0_0_1: Self = Self(Cow::Borrowed(FMT_OPEN_METRICS_0_0_1));

    /// Creates a [`Format`] from a raw `Content-Type` string.
    #[must_use]
    pub fn new(raw: impl Into<Cow<'static, str>>) -> Self {
        Self(raw.into())
    }

    /// Returns the baseline [`Format`] for the given [`FormatType`], using the latest stable
    /// version when multiple versions exist (`1.0.0` for [`FormatType::OpenMetrics`]).
    #[must_use]
    pub const fn from_type(t: FormatType) -> Self {
        match t {
            FormatType::ProtoCompact => Self::PROTO_COMPACT,
            FormatType::ProtoDelim => Self::PROTO_DELIM,
            FormatType::ProtoText => Self::PROTO_TEXT,
            FormatType::TextPlain => Self::TEXT,
            FormatType::OpenMetrics => Self::OPEN_METRICS_1_0_0,
            FormatType::Unknown => Self::UNKNOWN,
        }
    }

    /// Returns the baseline OpenMetrics [`Format`] for the given version string.
    pub fn new_open_metrics(version: &str) -> Result<Self, UnknownOpenMetricsVersionError> {
        match version {
            OPEN_METRICS_VERSION_0_0_1 => Ok(Self::OPEN_METRICS_0_0_1),
            OPEN_METRICS_VERSION_1_0_0 => Ok(Self::OPEN_METRICS_1_0_0),
            OPEN_METRICS_VERSION_2_0_0_RC => Ok(Self::OPEN_METRICS_2_0_0_RC),
            OPEN_METRICS_VERSION_2_0_0 => Ok(Self::OPEN_METRICS_2_0_0),
            other => Err(UnknownOpenMetricsVersionError(other.to_owned())),
        }
    }

    /// Returns the underlying `Content-Type` string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Deduces the high-level [`FormatType`] from this format string, matching
    /// `Format.FormatType()` in `prometheus/common/expfmt`.
    #[must_use]
    pub fn format_type(&self) -> FormatType {
        let mut tokens = self.0.split(';');
        let Some(media_type) = tokens.next().map(str::trim) else {
            return FormatType::Unknown;
        };

        let mut params: HashMap<&str, &str> = HashMap::new();
        for token in tokens {
            let mut args = token.split('=');
            let (Some(k), Some(v), None) = (args.next(), args.next(), args.next()) else {
                continue;
            };
            params.insert(k.trim(), v.trim());
        }

        match media_type {
            PROTO_TYPE => {
                if params.get(PROTO_KEY).copied() != Some(PROTO_PROTOCOL) {
                    return FormatType::Unknown;
                }
                match params.get(ENCODING_KEY).copied() {
                    Some(ENCODING_DELIMITED) => FormatType::ProtoDelim,
                    Some(ENCODING_TEXT) => FormatType::ProtoText,
                    Some(ENCODING_COMPACT_TEXT) => FormatType::ProtoCompact,
                    _ => FormatType::Unknown,
                }
            }
            OPEN_METRICS_TYPE => {
                if params.get(CHARSET_KEY).copied() != Some(CHARSET_UTF8) {
                    return FormatType::Unknown;
                }
                FormatType::OpenMetrics
            }
            TEXT_TYPE => match params.get(VERSION_KEY).copied() {
                None | Some(TEXT_VERSION) => FormatType::TextPlain,
                Some(_) => FormatType::Unknown,
            },
            _ => FormatType::Unknown,
        }
    }

    /// Returns the `version` parameter of the media type, or `""` if absent or if the media type
    /// cannot be parsed.
    #[must_use]
    pub fn version(&self) -> &str {
        let Some((_, params)) = parse_media_type(&self.0) else {
            return "";
        };
        params.get(VERSION_KEY).copied().unwrap_or("")
    }

    /// Returns whether this format is OpenMetrics 2.0 (`2.0.0` or `2.0.0-rc`).
    #[must_use]
    pub fn is_open_metrics_2_0(&self) -> bool {
        self.format_type() == FormatType::OpenMetrics && is_open_metrics_20_version(self.version())
    }

    /// Returns a copy of this [`Format`] with `escaping=<scheme>` appended to the end, removing
    /// any existing `escaping=...` parameters.
    #[must_use]
    pub fn with_escaping_scheme(&self, scheme: EscapingScheme) -> Self {
        let mut terms: Vec<String> = Vec::new();
        for p in self.0.split(';') {
            let mut tokens = p.split('=');
            let (Some(k), Some(_), None) = (tokens.next(), tokens.next(), tokens.next()) else {
                let trimmed = p.trim();
                if !trimmed.is_empty() {
                    terms.push(trimmed.to_owned());
                }
                continue;
            };
            if k.trim() != ESCAPING_KEY {
                terms.push(p.trim().to_owned());
            }
        }
        terms.push(format!("{ESCAPING_KEY}={scheme}"));
        Self(Cow::Owned(terms.join("; ")))
    }

    /// Extracts the [`EscapingScheme`] from this [`Format`], falling back to
    /// [`EscapingScheme::EscapeUnderscores`] (`model.NameEscapingScheme` default) when absent or invalid.
    #[must_use]
    pub fn to_escaping_scheme(&self) -> EscapingScheme {
        self.to_escaping_scheme_with_default(EscapingScheme::default())
    }

    /// Extracts the [`EscapingScheme`] from this [`Format`], falling back to `default_scheme`
    /// when no valid `escaping=...` term is present.
    #[must_use]
    pub fn to_escaping_scheme_with_default(
        &self,
        default_scheme: EscapingScheme,
    ) -> EscapingScheme {
        for p in self.0.split(';') {
            let mut tokens = p.split('=');
            let (Some(k), Some(v), None) = (tokens.next(), tokens.next(), tokens.next()) else {
                continue;
            };
            if k.trim() == ESCAPING_KEY {
                return v.trim().parse().unwrap_or(default_scheme);
            }
        }
        default_scheme
    }
}

impl fmt::Display for Format {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<&'static str> for Format {
    fn from(s: &'static str) -> Self {
        Self(Cow::Borrowed(s))
    }
}

impl From<String> for Format {
    fn from(s: String) -> Self {
        Self(Cow::Owned(s))
    }
}

impl AsRef<str> for Format {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// Standard accepted formats for [`negotiate`], ordered by preference.
pub const DEFAULT_ACCEPTED_FORMATS: &[Format] = &[
    Format::PROTO_DELIM,
    Format::PROTO_TEXT,
    Format::PROTO_COMPACT,
    Format::TEXT,
];

/// Standard accepted formats including stable OpenMetrics formats for
/// [`negotiate_including_open_metrics`], ordered by preference.
pub const DEFAULT_OPEN_METRICS_ACCEPTED_FORMATS: &[Format] = &[
    Format::OPEN_METRICS_1_0_0,
    Format::OPEN_METRICS_0_0_1,
    Format::PROTO_DELIM,
    Format::PROTO_TEXT,
    Format::PROTO_COMPACT,
    Format::TEXT,
];

/// Extracts the baseline [`Format`] from an HTTP response `Content-Type` header value,
/// matching `ResponseFormat` in `prometheus/common/expfmt/decode.go`.
#[must_use]
pub fn response_format(content_type: &str) -> Format {
    let Some((media_type, params)) = parse_media_type(content_type) else {
        return Format::UNKNOWN;
    };

    match media_type {
        PROTO_TYPE => {
            if let Some(&p) = params.get(PROTO_KEY)
                && p != PROTO_PROTOCOL
            {
                return Format::UNKNOWN;
            }
            if let Some(&e) = params.get(ENCODING_KEY)
                && e != ENCODING_DELIMITED
            {
                return Format::UNKNOWN;
            }
            Format::PROTO_DELIM
        }
        TEXT_TYPE => {
            if let Some(&v) = params.get(VERSION_KEY)
                && v != TEXT_VERSION
            {
                return Format::UNKNOWN;
            }
            Format::TEXT
        }
        OPEN_METRICS_TYPE => match params.get(VERSION_KEY).copied() {
            None | Some(OPEN_METRICS_VERSION_0_0_1) => Format::OPEN_METRICS_0_0_1,
            Some(OPEN_METRICS_VERSION_1_0_0) => Format::OPEN_METRICS_1_0_0,
            Some(_) => Format::UNKNOWN,
        },
        _ => Format::UNKNOWN,
    }
}

/// Negotiates a response [`Format`] from an HTTP `Accept` header value using
/// [`DEFAULT_ACCEPTED_FORMATS`] and `default_escaping`.
#[must_use]
pub fn negotiate(accept_header: &str, default_escaping: EscapingScheme) -> Format {
    negotiate_accept(accept_header, DEFAULT_ACCEPTED_FORMATS, default_escaping)
}

/// Negotiates a response [`Format`] from an HTTP `Accept` header value using
/// [`DEFAULT_OPEN_METRICS_ACCEPTED_FORMATS`] and `default_escaping`.
#[must_use]
pub fn negotiate_including_open_metrics(
    accept_header: &str,
    default_escaping: EscapingScheme,
) -> Format {
    negotiate_accept(
        accept_header,
        DEFAULT_OPEN_METRICS_ACCEPTED_FORMATS,
        default_escaping,
    )
}

/// Negotiates a response [`Format`] from an HTTP `Accept` header value and an ordered slice of
/// `accepted` formats, matching `NegotiateAccept` in `prometheus/common/expfmt/encode.go`.
#[must_use]
pub fn negotiate_accept(
    accept_header: &str,
    accepted: &[Format],
    default_escaping: EscapingScheme,
) -> Format {
    let default_suffix = format!("; {ESCAPING_KEY}={default_escaping}");
    for ac in parse_accept(accept_header) {
        for f in accepted {
            if match_format(&ac, f) {
                let suffix = escaping_for(&ac, f, default_escaping);
                return Format::new(format!("{f}{suffix}"));
            }
        }
    }
    for f in accepted {
        if f.format_type() == FormatType::TextPlain {
            return Format::new(format!("{f}{default_suffix}"));
        }
    }
    if let Some(first) = accepted.first() {
        return Format::new(format!("{first}{default_suffix}"));
    }
    Format::new(format!("{}{default_suffix}", Format::TEXT))
}

fn is_open_metrics_20_version(v: &str) -> bool {
    v == OPEN_METRICS_VERSION_2_0_0 || v == OPEN_METRICS_VERSION_2_0_0_RC
}

fn escaping_for(ac: &AcceptClause<'_>, f: &Format, default_escaping: EscapingScheme) -> String {
    if let Some(&p) = ac.params.get(ESCAPING_KEY)
        && p.parse::<EscapingScheme>().is_ok()
    {
        // An explicit valid escaping request wins, including for OpenMetrics 2.0.
        return format!("; {ESCAPING_KEY}={p}");
    }
    if f.format_type() == FormatType::OpenMetrics && is_open_metrics_20_version(f.version()) {
        // OpenMetrics 2.0 is UTF-8 native, so requesting it implies UTF-8 name support.
        return format!("; {ESCAPING_KEY}={}", EscapingScheme::AllowUtf8);
    }
    format!("; {ESCAPING_KEY}={default_escaping}")
}

#[derive(Clone, Debug)]
struct AcceptClause<'a> {
    main_type: &'a str,
    sub_type: &'a str,
    q: f64,
    params: HashMap<&'a str, &'a str>,
}

/// Parses an HTTP `Accept` header into quality-ordered clauses matching `goautoneg.ParseAccept`.
fn parse_accept(header: &str) -> Vec<AcceptClause<'_>> {
    if header.trim().is_empty() {
        return Vec::new();
    }
    let mut clauses = Vec::new();
    for part in header.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let mut subparts = part.split(';');
        let Some(media_range) = subparts.next().map(str::trim) else {
            continue;
        };
        let mut type_parts = media_range.split('/');
        let (Some(main_type), Some(sub_type), None) =
            (type_parts.next(), type_parts.next(), type_parts.next())
        else {
            continue;
        };

        let mut q = 1.0_f64;
        let mut params = HashMap::new();
        for sp in subparts {
            let sp = sp.trim();
            if sp.is_empty() {
                continue;
            }
            let mut kv = sp.split('=');
            let (Some(k), Some(v), None) = (kv.next(), kv.next(), kv.next()) else {
                continue;
            };
            let k = k.trim();
            let v = v.trim();
            if k == "q" {
                match v.parse::<f64>() {
                    Ok(parsed_q) if (0.0..=1.0).contains(&parsed_q) => q = parsed_q,
                    _ => q = 0.0,
                }
            } else {
                params.insert(k, v);
            }
        }
        clauses.push(AcceptClause {
            main_type: main_type.trim(),
            sub_type: sub_type.trim(),
            q,
            params,
        });
    }
    // NOTE: Stable sort preserves header order for clauses with equal quality factors.
    clauses.sort_by(|a, b| b.q.total_cmp(&a.q));
    clauses
}

fn match_format(ac: &AcceptClause<'_>, f: &Format) -> bool {
    let parsed = parse_accept(f.as_str());
    let Some(target) = parsed.first() else {
        return false;
    };

    if ac.main_type != "*" && ac.main_type != target.main_type {
        return false;
    }
    if ac.sub_type != "*" && ac.sub_type != target.sub_type {
        return false;
    }

    let mut ac_version = ac.params.get(VERSION_KEY).copied().unwrap_or("");
    if ac_version.is_empty() && ac.main_type == "application" && ac.sub_type == "openmetrics-text" {
        ac_version = OPEN_METRICS_VERSION_0_0_1;
    }
    if ac_version.is_empty() && ac.main_type == "text" && ac.sub_type == "plain" {
        ac_version = TEXT_VERSION;
    }

    for (&k, &v) in &target.params {
        if k == CHARSET_KEY {
            continue;
        }
        let ac_val = if k == VERSION_KEY {
            ac_version
        } else {
            ac.params.get(k).copied().unwrap_or("")
        };
        if ac_val != v {
            return false;
        }
    }

    true
}

/// Minimal RFC 1521 / `mime.ParseMediaType` parser for `type/subtype; key=val` strings.
fn parse_media_type(input: &str) -> Option<(&str, HashMap<&str, &str>)> {
    let mut parts = input.split(';');
    let base = parts.next()?.trim();
    let (main_type, sub_type) = base.split_once('/')?;
    if !is_valid_token(main_type) || !is_valid_token(sub_type) {
        return None;
    }

    let mut params = HashMap::new();
    for raw_param in parts {
        let trimmed = raw_param.trim();
        if trimmed.is_empty() {
            continue;
        }
        let (k, v) = trimmed.split_once('=')?;
        let k = k.trim();
        let v = v.trim().trim_matches('"');
        if !is_valid_token(k) || v.is_empty() {
            return None;
        }
        params.insert(k, v);
    }
    Some((base, params))
}

fn is_valid_token(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'+'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn to_format_type() {
        let cases = [
            (Format::PROTO_COMPACT, FormatType::ProtoCompact),
            (Format::PROTO_DELIM, FormatType::ProtoDelim),
            (Format::PROTO_TEXT, FormatType::ProtoText),
            (Format::OPEN_METRICS_2_0_0_RC, FormatType::OpenMetrics),
            (Format::OPEN_METRICS_2_0_0, FormatType::OpenMetrics),
            (Format::OPEN_METRICS_1_0_0, FormatType::OpenMetrics),
            (Format::TEXT, FormatType::TextPlain),
            (Format::OPEN_METRICS_0_0_1, FormatType::OpenMetrics),
            (
                Format::from("application/vnd.google.protobuf; proto=BadProtocol; encoding=text"),
                FormatType::Unknown,
            ),
            (
                Format::from("application/vnd.google.protobuf"),
                FormatType::Unknown,
            ),
            (
                Format::from(
                    "application/vnd.google.protobuf; proto=io.prometheus.client.MetricFamily=bad",
                ),
                FormatType::Unknown,
            ),
            (
                Format::from(
                    "application/vnd.google.protobuf; proto=io.prometheus.client.MetricFamily",
                ),
                FormatType::Unknown,
            ),
            (
                Format::from(
                    "application/vnd.google.protobuf; proto=io.prometheus.client.MetricFamily; encoding=textual",
                ),
                FormatType::Unknown,
            ),
            (
                Format::from("application/openmetrics-text; version=1.0.0; charset=ascii"),
                FormatType::Unknown,
            ),
            (Format::from("text/plain"), FormatType::TextPlain),
            (
                Format::from("text/plain; version=invalid"),
                FormatType::Unknown,
            ),
            (Format::from("gobbledygook"), FormatType::Unknown),
        ];

        for (format, expected) in cases {
            assert_eq!(format.format_type(), expected, "format={format}");
        }
    }

    #[test]
    fn to_escaping_scheme() {
        let cases = [
            (
                Format::PROTO_COMPACT,
                EscapingScheme::EscapeUnderscores,
                EscapingScheme::EscapeUnderscores,
            ),
            (
                Format::from(
                    "application/openmetrics-text; version=1.0.0; charset=utf-8; escaping=dots",
                ),
                EscapingScheme::EscapeUnderscores,
                EscapingScheme::EscapeDots,
            ),
            (
                Format::from(
                    "application/openmetrics-text; version=1.0.0; charset=utf-8; escaping=allow-utf-8",
                ),
                EscapingScheme::EscapeUnderscores,
                EscapingScheme::AllowUtf8,
            ),
            (
                Format::from(
                    "application/openmetrics-text; version=1.0.0; charset=utf-8; escaping=invalid",
                ),
                EscapingScheme::EscapeValues,
                EscapingScheme::EscapeValues,
            ),
        ];

        for (format, default_scheme, expected) in cases {
            assert_eq!(
                format.to_escaping_scheme_with_default(default_scheme),
                expected,
                "format={format}"
            );
        }

        assert_eq!(EscapingScheme::default(), EscapingScheme::EscapeUnderscores);
        assert_eq!(
            Format::PROTO_COMPACT.to_escaping_scheme(),
            EscapingScheme::EscapeUnderscores
        );
    }

    #[test]
    fn with_escaping_scheme() {
        let cases = [
            (
                "no existing term, append one",
                Format::PROTO_COMPACT,
                EscapingScheme::EscapeDots,
                "application/vnd.google.protobuf; proto=io.prometheus.client.MetricFamily; encoding=compact-text; escaping=dots",
            ),
            (
                "existing term at end, replace",
                Format::from(
                    "application/openmetrics-text; version=1.0.0; charset=utf-8; escaping=underscores",
                ),
                EscapingScheme::EscapeValues,
                "application/openmetrics-text; version=1.0.0; charset=utf-8; escaping=values",
            ),
            (
                "existing term in middle, replace",
                Format::from(
                    "application/openmetrics-text; escaping=dots; version=1.0.0; charset=utf-8; ",
                ),
                EscapingScheme::AllowUtf8,
                "application/openmetrics-text; version=1.0.0; charset=utf-8; escaping=allow-utf-8",
            ),
            (
                "multiple existing terms removed",
                Format::from(
                    "application/openmetrics-text; escaping=dots; version=1.0.0; charset=utf-8; escaping=allow-utf-8",
                ),
                EscapingScheme::EscapeValues,
                "application/openmetrics-text; version=1.0.0; charset=utf-8; escaping=values",
            ),
        ];

        for (name, format, scheme, expected) in cases {
            assert_eq!(
                format.with_escaping_scheme(scheme).as_str(),
                expected,
                "case={name}"
            );
        }
    }

    #[test]
    fn format_version() {
        let cases = [
            (Format::TEXT, "0.0.4"),
            (
                Format::TEXT.with_escaping_scheme(EscapingScheme::AllowUtf8),
                "0.0.4",
            ),
            (Format::OPEN_METRICS_0_0_1, "0.0.1"),
            (Format::OPEN_METRICS_1_0_0, "1.0.0"),
            (Format::OPEN_METRICS_2_0_0_RC, "2.0.0-rc"),
            (
                Format::OPEN_METRICS_2_0_0_RC.with_escaping_scheme(EscapingScheme::EscapeDots),
                "2.0.0-rc",
            ),
            (Format::OPEN_METRICS_2_0_0, "2.0.0"),
            (
                Format::OPEN_METRICS_2_0_0.with_escaping_scheme(EscapingScheme::EscapeDots),
                "2.0.0",
            ),
            (Format::PROTO_DELIM, ""),
            (Format::PROTO_TEXT, ""),
            (Format::PROTO_COMPACT, ""),
            (Format::UNKNOWN, ""),
            (Format::from("invalid"), ""),
        ];

        for (format, expected) in cases {
            assert_eq!(format.version(), expected, "format={format}");
        }
    }

    #[test]
    fn negotiate_default() {
        let prefix = "application/vnd.google.protobuf;proto=io.prometheus.client.MetricFamily";
        let cases = [
            (
                "delimited format",
                format!("{prefix};encoding=delimited"),
                "application/vnd.google.protobuf; proto=io.prometheus.client.MetricFamily; encoding=delimited; escaping=underscores",
            ),
            (
                "text format",
                format!("{prefix};encoding=text"),
                "application/vnd.google.protobuf; proto=io.prometheus.client.MetricFamily; encoding=text; escaping=underscores",
            ),
            (
                "compact text format",
                format!("{prefix};encoding=compact-text"),
                "application/vnd.google.protobuf; proto=io.prometheus.client.MetricFamily; encoding=compact-text; escaping=underscores",
            ),
            (
                "plain text format",
                "text/plain;version=0.0.4".to_owned(),
                "text/plain; version=0.0.4; charset=utf-8; escaping=underscores",
            ),
            (
                "delimited format utf-8",
                format!("{prefix};encoding=delimited; escaping=allow-utf-8;"),
                "application/vnd.google.protobuf; proto=io.prometheus.client.MetricFamily; encoding=delimited; escaping=allow-utf-8",
            ),
            (
                "text format utf-8",
                format!("{prefix};encoding=text; escaping=allow-utf-8;"),
                "application/vnd.google.protobuf; proto=io.prometheus.client.MetricFamily; encoding=text; escaping=allow-utf-8",
            ),
            (
                "compact text format utf-8",
                format!("{prefix};encoding=compact-text; escaping=allow-utf-8;"),
                "application/vnd.google.protobuf; proto=io.prometheus.client.MetricFamily; encoding=compact-text; escaping=allow-utf-8",
            ),
            (
                "plain text format 0.0.4 trailing semicolon",
                "text/plain;version=0.0.4;".to_owned(),
                "text/plain; version=0.0.4; charset=utf-8; escaping=underscores",
            ),
            (
                "plain text format 0.0.4 escaping=values",
                "text/plain;version=0.0.4; escaping=values;".to_owned(),
                "text/plain; version=0.0.4; charset=utf-8; escaping=values",
            ),
            (
                "wildcard */*",
                "*/*".to_owned(),
                "text/plain; version=0.0.4; charset=utf-8; escaping=underscores",
            ),
            (
                "browser Accept header with wildcard",
                "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8".to_owned(),
                "text/plain; version=0.0.4; charset=utf-8; escaping=underscores",
            ),
            (
                "json with wildcard fallback",
                "application/json, */*".to_owned(),
                "text/plain; version=0.0.4; charset=utf-8; escaping=underscores",
            ),
        ];

        for (name, accept, expected) in cases {
            let actual = negotiate(&accept, EscapingScheme::EscapeUnderscores);
            assert_eq!(actual.as_str(), expected, "case={name}");
        }
    }

    #[test]
    fn negotiate_open_metrics() {
        let prefix = "application/vnd.google.protobuf;proto=io.prometheus.client.MetricFamily";
        let cases = [
            (
                "OM format, no version",
                "application/openmetrics-text".to_owned(),
                "application/openmetrics-text; version=0.0.1; charset=utf-8; escaping=values",
            ),
            (
                "OM format, 0.0.1 version",
                "application/openmetrics-text;version=0.0.1; escaping=underscores".to_owned(),
                "application/openmetrics-text; version=0.0.1; charset=utf-8; escaping=underscores",
            ),
            (
                "OM format, 1.0.0 version",
                "application/openmetrics-text;version=1.0.0".to_owned(),
                "application/openmetrics-text; version=1.0.0; charset=utf-8; escaping=values",
            ),
            (
                "OM format, 2.0.0 version not in default OM accepted",
                "application/openmetrics-text;version=2.0.0".to_owned(),
                "text/plain; version=0.0.4; charset=utf-8; escaping=values",
            ),
            (
                "OM format, invalid version",
                "application/openmetrics-text;version=0.0.4".to_owned(),
                "text/plain; version=0.0.4; charset=utf-8; escaping=values",
            ),
            (
                "compact text format",
                format!("{prefix};encoding=compact-text; escaping=underscores"),
                "application/vnd.google.protobuf; proto=io.prometheus.client.MetricFamily; encoding=compact-text; escaping=underscores",
            ),
            (
                "plain text format 0.0.4 allow-utf-8",
                "text/plain;version=0.0.4; escaping=allow-utf-8".to_owned(),
                "text/plain; version=0.0.4; charset=utf-8; escaping=allow-utf-8",
            ),
            (
                "wildcard */*",
                "*/*".to_owned(),
                "text/plain; version=0.0.4; charset=utf-8; escaping=values",
            ),
        ];

        for (name, accept, expected) in cases {
            let actual = negotiate_including_open_metrics(&accept, EscapingScheme::EscapeValues);
            assert_eq!(actual.as_str(), expected, "case={name}");
        }
    }

    #[test]
    fn negotiate_accept_custom() {
        let cases: &[(&str, &str, &[Format], &str)] = &[
            (
                "requested OM 2.0-rc, accepted OM 2.0-rc",
                "application/openmetrics-text;version=2.0.0-rc",
                &[Format::OPEN_METRICS_2_0_0_RC, Format::TEXT],
                "application/openmetrics-text; version=2.0.0-rc; charset=utf-8; escaping=allow-utf-8",
            ),
            (
                "requested OM 2.0-rc with explicit escaping",
                "application/openmetrics-text;version=2.0.0-rc;escaping=underscores",
                &[Format::OPEN_METRICS_2_0_0_RC, Format::TEXT],
                "application/openmetrics-text; version=2.0.0-rc; charset=utf-8; escaping=underscores",
            ),
            (
                "requested OM 2.0, accepted OM 2.0",
                "application/openmetrics-text;version=2.0.0",
                &[Format::OPEN_METRICS_2_0_0, Format::TEXT],
                "application/openmetrics-text; version=2.0.0; charset=utf-8; escaping=allow-utf-8",
            ),
            (
                "requested OM 2.0 with explicit escaping",
                "application/openmetrics-text;version=2.0.0;escaping=underscores",
                &[Format::OPEN_METRICS_2_0_0, Format::TEXT],
                "application/openmetrics-text; version=2.0.0; charset=utf-8; escaping=underscores",
            ),
            (
                "requested OM 2.0 with unknown escaping",
                "application/openmetrics-text;version=2.0.0;escaping=foo",
                &[Format::OPEN_METRICS_2_0_0, Format::TEXT],
                "application/openmetrics-text; version=2.0.0; charset=utf-8; escaping=allow-utf-8",
            ),
            (
                "requested OM 1.0 without escaping keeps the default",
                "application/openmetrics-text;version=1.0.0",
                &[
                    Format::OPEN_METRICS_2_0_0,
                    Format::OPEN_METRICS_1_0_0,
                    Format::TEXT,
                ],
                "application/openmetrics-text; version=1.0.0; charset=utf-8; escaping=values",
            ),
            (
                "escaping from a skipped clause is not applied to the match",
                "application/json;escaping=allow-utf-8, text/plain;version=0.0.4",
                &[Format::PROTO_DELIM, Format::TEXT],
                "text/plain; version=0.0.4; charset=utf-8; escaping=values",
            ),
            (
                "requested OM 2.0, not accepted, falls back to text",
                "application/openmetrics-text;version=2.0.0",
                &[Format::OPEN_METRICS_1_0_0, Format::TEXT],
                "text/plain; version=0.0.4; charset=utf-8; escaping=values",
            ),
            (
                "requested OM 2.0, not accepted, falls back to first format when no text in accepted",
                "application/openmetrics-text;version=2.0.0",
                &[Format::PROTO_DELIM],
                "application/vnd.google.protobuf; proto=io.prometheus.client.MetricFamily; encoding=delimited; escaping=values",
            ),
            (
                "requested OM 1.0 and 2.0, prefers higher q value",
                "application/openmetrics-text;version=1.0.0;q=0.8, application/openmetrics-text;version=2.0.0;q=0.9",
                &[
                    Format::OPEN_METRICS_1_0_0,
                    Format::OPEN_METRICS_2_0_0,
                    Format::TEXT,
                ],
                "application/openmetrics-text; version=2.0.0; charset=utf-8; escaping=allow-utf-8",
            ),
            (
                "wildcard */* matches text format if present",
                "*/*",
                &[
                    Format::OPEN_METRICS_2_0_0,
                    Format::PROTO_DELIM,
                    Format::TEXT,
                ],
                "text/plain; version=0.0.4; charset=utf-8; escaping=values",
            ),
            (
                "wildcard */* with text first in accepted",
                "*/*",
                &[Format::TEXT, Format::PROTO_DELIM],
                "text/plain; version=0.0.4; charset=utf-8; escaping=values",
            ),
            (
                "wildcard */* falls back to first format when no text in accepted",
                "*/*",
                &[Format::OPEN_METRICS_2_0_0, Format::PROTO_DELIM],
                "application/openmetrics-text; version=2.0.0; charset=utf-8; escaping=values",
            ),
            (
                "unversioned text/plain matches FmtText",
                "text/plain",
                &[Format::PROTO_DELIM, Format::TEXT],
                "text/plain; version=0.0.4; charset=utf-8; escaping=values",
            ),
            (
                "empty accepted list defaults to FmtText",
                "application/unknown",
                &[],
                "text/plain; version=0.0.4; charset=utf-8; escaping=values",
            ),
        ];

        for (name, accept, accepted, expected) in cases {
            let actual = negotiate_accept(accept, accepted, EscapingScheme::EscapeValues);
            assert_eq!(actual.as_str(), *expected, "case={name}");
        }
    }

    #[test]
    fn response_format_extraction() {
        assert_eq!(response_format(FMT_TEXT), Format::TEXT);
        assert_eq!(response_format("text/plain"), Format::TEXT);
        assert_eq!(
            response_format("text/plain; version=0.0.5"),
            Format::UNKNOWN
        );
        assert_eq!(
            response_format(FMT_OPEN_METRICS_0_0_1),
            Format::OPEN_METRICS_0_0_1
        );
        assert_eq!(
            response_format("application/openmetrics-text"),
            Format::OPEN_METRICS_0_0_1
        );
        assert_eq!(
            response_format(FMT_OPEN_METRICS_1_0_0),
            Format::OPEN_METRICS_1_0_0
        );
        assert_eq!(response_format(FMT_OPEN_METRICS_2_0_0), Format::UNKNOWN);
        assert_eq!(
            response_format("application/openmetrics-text; version=0.0.4"),
            Format::UNKNOWN
        );
        assert_eq!(response_format(FMT_PROTO_DELIM), Format::PROTO_DELIM);
        assert_eq!(response_format(FMT_PROTO_TEXT), Format::UNKNOWN);
        assert_eq!(response_format("invalid"), Format::UNKNOWN);
    }
}
