// Copyright 2026 SEQSENSE, Inc.
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

package collector

import (
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"

	"github.com/seqsense/aws-iot-device-sdk-go/v6/defender"
)

func testAddrs() (map[string]string, error) {
	return map[string]string{
		"127.0.0.1":    "lo",
		"::1":          "lo",
		"192.168.1.10": "eth0",
	}, nil
}

func copyProc(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "net"), 0755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"dev", "tcp", "tcp6", "udp", "udp6"} {
		b, err := os.ReadFile(filepath.Join("testdata", "proc", "net", name))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, "net", name), b, 0644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestCollect(t *testing.T) {
	root := copyProc(t)
	c := New(WithProcRoot(root))
	c.opts.interfaceAddrs = testAddrs

	m, err := c.Collect()
	if err != nil {
		t.Fatal(err)
	}

	expected := &defender.Metrics{
		ListeningTCPPorts: &defender.ListeningPorts{
			Ports: []defender.Port{
				{Port: 22},
				{Port: 631, Interface: "lo"},
			},
			Total: 2,
		},
		ListeningUDPPorts: &defender.ListeningPorts{
			Ports: []defender.Port{
				{Port: 68},
				{Port: 323, Interface: "lo"},
				{Port: 5353},
			},
			Total: 3,
		},
		TCPConnections: &defender.TCPConnections{
			EstablishedConnections: []defender.Connection{
				{RemoteAddr: "192.168.1.20:54321", LocalPort: 22, LocalInterface: "eth0"},
				{RemoteAddr: "[::1]:8080", LocalPort: 50000, LocalInterface: "lo"},
			},
			Total: 2,
		},
	}
	if !reflect.DeepEqual(expected, m) {
		t.Fatalf("Expected:\n%+v\ngot:\n%+v", expected, m)
	}

	// Update counters and collect again to get network stats.
	dev := `Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo:    9000      90    0    0    0     0          0         0     9000      90    0    0    0     0       0          0
  eth0:    5500      55    0    0    0     0          0         0     3300      33    0    0    0     0       0          0
  eth1:     100       1    0    0    0     0          0         0      200       2    0    0    0     0       0          0
`
	if err := os.WriteFile(filepath.Join(root, "net", "dev"), []byte(dev), 0644); err != nil {
		t.Fatal(err)
	}
	m, err = c.Collect()
	if err != nil {
		t.Fatal(err)
	}
	expectedStats := &defender.NetworkStats{
		BytesIn:    600,
		BytesOut:   500,
		PacketsIn:  6,
		PacketsOut: 5,
	}
	if !reflect.DeepEqual(expectedStats, m.NetworkStats) {
		t.Errorf("Expected: %+v, got: %+v", expectedStats, m.NetworkStats)
	}
}

func TestCollect_MaxListSize(t *testing.T) {
	c := New(WithProcRoot(copyProc(t)), WithMaxListSize(1))
	c.opts.interfaceAddrs = testAddrs

	m, err := c.Collect()
	if err != nil {
		t.Fatal(err)
	}
	if n := len(m.ListeningTCPPorts.Ports); n != 1 {
		t.Errorf("Expected 1 port, got %d", n)
	}
	if m.ListeningTCPPorts.Total != 2 {
		t.Errorf("Expected total 2, got %d", m.ListeningTCPPorts.Total)
	}
	if n := len(m.TCPConnections.EstablishedConnections); n != 1 {
		t.Errorf("Expected 1 connection, got %d", n)
	}
	if m.TCPConnections.Total != 2 {
		t.Errorf("Expected total 2, got %d", m.TCPConnections.Total)
	}
}

func TestCollect_MissingIPv6(t *testing.T) {
	root := copyProc(t)
	for _, name := range []string{"tcp6", "udp6"} {
		if err := os.Remove(filepath.Join(root, "net", name)); err != nil {
			t.Fatal(err)
		}
	}
	c := New(WithProcRoot(root))
	c.opts.interfaceAddrs = testAddrs

	m, err := c.Collect()
	if err != nil {
		t.Fatal(err)
	}
	if m.ListeningUDPPorts.Total != 1 {
		t.Errorf("Expected 1 UDP port, got %d", m.ListeningUDPPorts.Total)
	}
	if m.TCPConnections.Total != 1 {
		t.Errorf("Expected 1 TCP connection, got %d", m.TCPConnections.Total)
	}
}

func TestCollect_System(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("procfs is not available")
	}
	c := New()
	for i := 0; i < 2; i++ {
		m, err := c.Collect()
		if err != nil {
			t.Fatal(err)
		}
		if m.ListeningTCPPorts == nil || m.ListeningUDPPorts == nil || m.TCPConnections == nil {
			t.Fatalf("Expected all socket metrics, got: %+v", m)
		}
		if i == 1 && m.NetworkStats == nil {
			t.Error("Expected network stats on second call")
		}
	}
}

func TestParseAddr(t *testing.T) {
	testCases := map[string]struct {
		ip   string
		port int
		err  bool
	}{
		"0100007F:0050":                         {ip: "127.0.0.1", port: 80},
		"00000000000000000000000001000000:01BB": {ip: "::1", port: 443},
		"0000000000000000FFFF00000A01A8C0:0016": {ip: "192.168.1.10", port: 22},
		"B80D0120000000000000000001000000:0035": {ip: "2001:db8::1", port: 53},
		"0100007F":                              {err: true},
		"ZZ00007F:0050":                         {err: true},
		"0100007F:ZZZZ":                         {err: true},
	}
	for in, testCase := range testCases {
		testCase := testCase
		t.Run(in, func(t *testing.T) {
			ip, port, err := parseAddr(in)
			if testCase.err {
				if err == nil {
					t.Fatal("Expected error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if ip.String() != testCase.ip || port != testCase.port {
				t.Errorf("Expected %s:%d, got %s:%d", testCase.ip, testCase.port, ip, port)
			}
		})
	}
}
