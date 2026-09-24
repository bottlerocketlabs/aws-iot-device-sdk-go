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

package defender

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestMarshalReport(t *testing.T) {
	metrics := &Metrics{
		ListeningTCPPorts: &ListeningPorts{
			Ports: []Port{
				{Port: 22, Interface: "eth0"},
				{Port: 80},
			},
		},
		ListeningUDPPorts: &ListeningPorts{
			Ports: []Port{{Port: 53}},
			Total: 5,
		},
		NetworkStats: &NetworkStats{
			BytesIn:    1,
			BytesOut:   2,
			PacketsIn:  3,
			PacketsOut: 4,
		},
		TCPConnections: &TCPConnections{
			EstablishedConnections: []Connection{
				{RemoteAddr: "192.168.0.1:8000", LocalPort: 5000, LocalInterface: "eth0"},
			},
		},
		CustomMetrics: map[string]CustomMetric{
			"cpu":   Number(12.5),
			"temps": NumberList(1, 2),
			"users": StringList("a", "b"),
			"peers": IPList("10.0.0.1"),
		},
	}

	testCases := map[string]struct {
		metrics  *Metrics
		short    bool
		expected string
	}{
		"Empty": {
			metrics:  &Metrics{},
			expected: `{"header":{"report_id":123,"version":"1.0"},"metrics":{}}`,
		},
		"EmptyListsOmitted": {
			metrics: &Metrics{
				ListeningTCPPorts: &ListeningPorts{},
				ListeningUDPPorts: &ListeningPorts{Ports: []Port{}},
				TCPConnections:    &TCPConnections{},
				CustomMetrics:     map[string]CustomMetric{},
			},
			expected: `{"header":{"report_id":123,"version":"1.0"},"metrics":{}}`,
		},
		"TotalSmallerThanList": {
			metrics: &Metrics{
				ListeningTCPPorts: &ListeningPorts{Ports: []Port{{Port: 22}, {Port: 80}}, Total: 1},
			},
			expected: `{"header":{"report_id":123,"version":"1.0"},"metrics":{
				"listening_tcp_ports":{"ports":[{"port":22},{"port":80}],"total":2}
			}}`,
		},
		"Long": {
			metrics: metrics,
			expected: `{
				"custom_metrics":{
					"cpu":[{"number":12.5}],
					"peers":[{"ip_list":["10.0.0.1"]}],
					"temps":[{"number_list":[1,2]}],
					"users":[{"string_list":["a","b"]}]
				},
				"header":{"report_id":123,"version":"1.0"},
				"metrics":{
					"listening_tcp_ports":{"ports":[{"interface":"eth0","port":22},{"port":80}],"total":2},
					"listening_udp_ports":{"ports":[{"port":53}],"total":5},
					"network_stats":{"bytes_in":1,"bytes_out":2,"packets_in":3,"packets_out":4},
					"tcp_connections":{"established_connections":{
						"connections":[{"local_interface":"eth0","local_port":5000,"remote_addr":"192.168.0.1:8000"}],
						"total":1
					}}
				}
			}`,
		},
		"Short": {
			metrics: metrics,
			short:   true,
			expected: `{
				"cmet":{
					"cpu":[{"number":12.5}],
					"peers":[{"ip_list":["10.0.0.1"]}],
					"temps":[{"number_list":[1,2]}],
					"users":[{"string_list":["a","b"]}]
				},
				"hed":{"rid":123,"v":"1.0"},
				"met":{
					"tp":{"pts":[{"if":"eth0","pt":22},{"pt":80}],"t":2},
					"up":{"pts":[{"pt":53}],"t":5},
					"ns":{"bi":1,"bo":2,"pi":3,"po":4},
					"tc":{"ec":{
						"cs":[{"li":"eth0","lp":5000,"rad":"192.168.0.1:8000"}],
						"t":1
					}}
				}
			}`,
		},
	}

	for name, testCase := range testCases {
		testCase := testCase
		t.Run(name, func(t *testing.T) {
			b, err := marshalReport(123, testCase.metrics, testCase.short)
			if err != nil {
				t.Fatal(err)
			}
			expected := &bytes.Buffer{}
			if err := json.Compact(expected, []byte(testCase.expected)); err != nil {
				t.Fatal(err)
			}
			// Normalize key order of expected JSON.
			var v interface{}
			if err := json.Unmarshal(expected.Bytes(), &v); err != nil {
				t.Fatal(err)
			}
			exp, err := json.Marshal(v)
			if err != nil {
				t.Fatal(err)
			}
			if string(exp) != string(b) {
				t.Errorf("Expected:\n%s\ngot:\n%s", string(exp), string(b))
			}
		})
	}
}
