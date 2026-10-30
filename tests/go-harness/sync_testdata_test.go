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
	"os"
	"path/filepath"
	"testing"
)

func TestExtractFuncInputLiteral(t *testing.T) {
	cases := []struct {
		name    string
		body    string
		want    string
		wantErr bool
	}{
		{
			name: "appends top-level literals in order",
			body: "input := `a\n`\n\tinput += \"b\"\n\tinput += \"\\n# EOF\\n\"",
			want: "a\nb\n# EOF\n",
		},
		{
			name: "ignores nested assignments",
			body: "input := \"a\"\n\tt.Run(\"x\", func(t *testing.T) { input := \"z\"; input += \"y\" })\n\tif true { input += \"w\" }",
			want: "a",
		},
		{
			name:    "rejects non-literal append",
			body:    "input := \"a\"\n\tinput += strings.Repeat(\"b\", 2)",
			wantErr: true,
		},
		{
			name:    "rejects reassignment",
			body:    "input := \"a\"\n\tinput = input + \"b\"",
			wantErr: true,
		},
		{
			name:    "rejects non-literal define",
			body:    "input := \"a\" + tc.input\n\tinput += \"b\"",
			wantErr: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srcFile := filepath.Join(t.TempDir(), "x_test.go")
			src := "package x\n\nfunc TestX(t *testing.T) {\n\t" + tc.body + "\n}\n"
			if err := os.WriteFile(srcFile, []byte(src), 0o644); err != nil {
				t.Fatal(err)
			}
			got, err := extractFuncInputLiteral(srcFile, "TestX")
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got %q", got)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}
