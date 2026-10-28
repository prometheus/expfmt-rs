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

package main

import (
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/model/textparse"
)

// promParseInputs are the Prometheus text fixtures, relative to testdata/, that
// tests/promparse_go_diff.rs parses and compares against the Go output.
var promParseInputs = []struct {
	input  string
	output string
}{
	{"textparse/TestPromParse.prom.txt", "TestPromParse.prom.txt.txt"},
	{"textparse/alltypes.237mfs.prom.txt", "alltypes.237mfs.prom.txt.txt"},
	{"textparse/alltypes.237mfs.nometa.prom.txt", "alltypes.237mfs.nometa.prom.txt.txt"},
	{"expfmt/text", "expfmt_text.txt"},
}

// writePromParseExpected runs textparse.NewPromParser on each input and writes
// one line per entry to testdata/promparse/.
func writePromParseExpected(outRoot string) ([]string, error) {
	dstDir := filepath.Join(outRoot, "promparse")
	if err := os.MkdirAll(dstDir, 0o755); err != nil {
		return nil, fmt.Errorf("mkdir %s: %w", dstDir, err)
	}
	var written []string
	for _, in := range promParseInputs {
		data, err := os.ReadFile(filepath.Join(outRoot, in.input))
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", in.input, err)
		}
		dstPath := filepath.Join(dstDir, in.output)
		if err := os.WriteFile(dstPath, []byte(renderPromParse(data)), 0o644); err != nil {
			return nil, fmt.Errorf("write %s: %w", dstPath, err)
		}
		written = append(written, "promparse/"+in.output)
	}
	return written, nil
}

func renderPromParse(data []byte) string {
	var out strings.Builder
	parser := textparse.NewPromParser(data, labels.NewSymbolTable(), false)
	var lset labels.Labels
	for {
		entry, err := parser.Next()
		if errors.Is(err, io.EOF) {
			return out.String()
		}
		if err != nil {
			out.WriteString("error\n")
			return out.String()
		}
		switch entry {
		case textparse.EntryHelp:
			name, text := parser.Help()
			fmt.Fprintf(&out, "help %s %s\n", quote(name), quote(text))
		case textparse.EntryType:
			name, mtype := parser.Type()
			fmt.Fprintf(&out, "type %s %s\n", quote(name), mtype)
		case textparse.EntryComment:
			fmt.Fprintf(&out, "comment %s\n", quote(parser.Comment()))
		case textparse.EntrySeries:
			series, ts, value := parser.Series()
			timestamp := "-"
			if ts != nil {
				timestamp = strconv.FormatInt(*ts, 10)
			}
			fmt.Fprintf(&out, "series %s %s %s", quote(series), formatValue(value), timestamp)
			parser.Labels(&lset)
			lset.Range(func(l labels.Label) {
				fmt.Fprintf(&out, " %s=%s", quote([]byte(l.Name)), quote([]byte(l.Value)))
			})
			out.WriteString("\n")
		}
	}
}

// quote escapes bytes instead of runes so Rust can reproduce it without Go's
// strconv.Quote rules for non-printable Unicode.
func quote(b []byte) string {
	var out strings.Builder
	out.WriteByte('"')
	for _, c := range b {
		switch {
		case c == '\\' || c == '"':
			out.WriteByte('\\')
			out.WriteByte(c)
		case c < 0x20 || c == 0x7f:
			fmt.Fprintf(&out, `\x%02x`, c)
		default:
			out.WriteByte(c)
		}
	}
	out.WriteByte('"')
	return out.String()
}

func formatValue(v float64) string {
	switch {
	case math.IsNaN(v):
		return "NaN"
	case math.IsInf(v, 1):
		return "+Inf"
	case math.IsInf(v, -1):
		return "-Inf"
	}
	return strconv.FormatFloat(v, 'e', -1, 64)
}
