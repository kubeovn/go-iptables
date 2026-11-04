// Copyright 2015 CoreOS, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package iptables

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func writeFakeIptables(t *testing.T, dir, name, mode string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	script := fmt.Sprintf("#!/bin/sh\n[ \"$1\" = --version ] || exit 1\nprintf 'iptables v1.8.9 (%s)\\n'\n", mode)
	if err := os.WriteFile(path, []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestCustomMode(t *testing.T) {
	for _, proto := range []Protocol{ProtocolIPv4, ProtocolIPv6} {
		for _, mode := range []string{"", "legacy", "nft"} {
			t.Run(fmt.Sprintf("%d/%s", proto, mode), func(t *testing.T) {
				dir := t.TempDir()
				name := "iptables"
				if proto == ProtocolIPv6 {
					name = "ip6tables"
				}
				if mode != "" {
					name += "-" + mode
				}
				detectedMode := "legacy"
				if mode == "nft" {
					detectedMode = "nf_tables"
				}
				path := writeFakeIptables(t, dir, name, detectedMode)
				t.Setenv("PATH", dir)

				constructors := []func() (*IPTables, error){
					func() (*IPTables, error) { return New(IPFamily(proto), Mode(mode)) },
					func() (*IPTables, error) { return NewWithProtocolAndMode(proto, mode) },
				}
				for _, newIPTables := range constructors {
					ipt, err := newIPTables()
					if err != nil {
						t.Fatal(err)
					}
					if ipt.path != path || ipt.Proto() != proto || ipt.mode != detectedMode {
						t.Fatalf("unexpected configuration: path=%s proto=%d mode=%s", ipt.path, ipt.Proto(), ipt.mode)
					}
				}
			})
		}
	}
}

func TestPathOverridesMode(t *testing.T) {
	for _, proto := range []Protocol{ProtocolIPv4, ProtocolIPv6} {
		t.Run(fmt.Sprint(proto), func(t *testing.T) {
			dir := t.TempDir()
			path := writeFakeIptables(t, dir, "custom-iptables", "nf_tables")
			t.Setenv("PATH", dir)
			for _, opts := range [][]option{
				{IPFamily(proto), Mode("missing"), Path(path)},
				{Path(path), Mode("missing"), IPFamily(proto)},
			} {
				ipt, err := New(opts...)
				if err != nil {
					t.Fatal(err)
				}
				if ipt.path != path || ipt.Proto() != proto || ipt.mode != "nf_tables" {
					t.Fatalf("explicit path was not preserved: path=%s proto=%d mode=%s", ipt.path, ipt.Proto(), ipt.mode)
				}
			}
		})
	}
}
