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

// promParseInputs are the Prometheus text fixtures, relative to testdata/. Each
// output is written to testdata/promparse/ under the same relative path, which is
// how src/parse/go_diff_tests.rs finds the input for each expected file.
var promParseInputs = []string{
	"textparse/TestPromParse.prom.txt",
	"textparse/alltypes.237mfs.prom.txt",
	"textparse/alltypes.237mfs.nometa.prom.txt",
	"expfmt/text",
}

// writePromParseExpected runs textparse.NewPromParser on each input and writes
// one line per entry to testdata/promparse/.
func writePromParseExpected(outRoot string) ([]string, error) {
	var written []string
	for _, input := range promParseInputs {
		data, err := os.ReadFile(filepath.Join(outRoot, input))
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", input, err)
		}
		dstPath := filepath.Join(outRoot, "promparse", input)
		if err := os.MkdirAll(filepath.Dir(dstPath), 0o755); err != nil {
			return nil, fmt.Errorf("mkdir %s: %w", filepath.Dir(dstPath), err)
		}
		if err := os.WriteFile(dstPath, []byte(renderPromParse(data)), 0o644); err != nil {
			return nil, fmt.Errorf("write %s: %w", dstPath, err)
		}
		written = append(written, "promparse/"+input)
	}
	return written, nil
}

func renderPromParse(data []byte) string {
	var out strings.Builder
	parser := textparse.NewPromParser(data, labels.NewSymbolTable(), false)
	var labelSet labels.Labels
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
			name, metricType := parser.Type()
			fmt.Fprintf(&out, "type %s %s\n", quote(name), metricType)
		case textparse.EntryComment:
			fmt.Fprintf(&out, "comment %s\n", quote(parser.Comment()))
		case textparse.EntrySeries:
			series, timestampMillis, value := parser.Series()
			timestamp := "-"
			if timestampMillis != nil {
				timestamp = strconv.FormatInt(*timestampMillis, 10)
			}
			fmt.Fprintf(&out, "series %s %016x %s", quote(series), math.Float64bits(value), timestamp)
			parser.Labels(&labelSet)
			labelSet.Range(func(label labels.Label) {
				fmt.Fprintf(&out, " %s=%s", quote([]byte(label.Name)), quote([]byte(label.Value)))
			})
			out.WriteString("\n")
		}
	}
}

// quote escapes bytes instead of runes so Rust can reproduce it without Go's
// strconv.Quote rules for non-printable Unicode.
func quote(raw []byte) string {
	var out strings.Builder
	out.WriteByte('"')
	for _, rawByte := range raw {
		switch {
		case rawByte == '\\' || rawByte == '"':
			out.WriteByte('\\')
			out.WriteByte(rawByte)
		case rawByte < 0x20 || rawByte == 0x7f:
			fmt.Fprintf(&out, `\x%02x`, rawByte)
		default:
			out.WriteByte(rawByte)
		}
	}
	out.WriteByte('"')
	return out.String()
}
