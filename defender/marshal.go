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
	"encoding/json"
)

const reportVersion = "1.0"

// fieldName is a field name of the metrics report in long and short form.
type fieldName struct {
	long, short string
}

// Field names of the metrics report.
var (
	fieldHeader                 = fieldName{"header", "hed"}
	fieldMetrics                = fieldName{"metrics", "met"}
	fieldReportID               = fieldName{"report_id", "rid"}
	fieldVersion                = fieldName{"version", "v"}
	fieldTCPConnections         = fieldName{"tcp_connections", "tc"}
	fieldEstablishedConnections = fieldName{"established_connections", "ec"}
	fieldConnections            = fieldName{"connections", "cs"}
	fieldRemoteAddr             = fieldName{"remote_addr", "rad"}
	fieldLocalPort              = fieldName{"local_port", "lp"}
	fieldLocalInterface         = fieldName{"local_interface", "li"}
	fieldListeningTCPPorts      = fieldName{"listening_tcp_ports", "tp"}
	fieldListeningUDPPorts      = fieldName{"listening_udp_ports", "up"}
	fieldPorts                  = fieldName{"ports", "pts"}
	fieldPort                   = fieldName{"port", "pt"}
	fieldInterface              = fieldName{"interface", "if"}
	fieldNetworkStats           = fieldName{"network_stats", "ns"}
	fieldBytesIn                = fieldName{"bytes_in", "bi"}
	fieldBytesOut               = fieldName{"bytes_out", "bo"}
	fieldPacketsIn              = fieldName{"packets_in", "pi"}
	fieldPacketsOut             = fieldName{"packets_out", "po"}
	fieldTotal                  = fieldName{"total", "t"}
	fieldCustomMetrics          = fieldName{"custom_metrics", "cmet"}
)

type jsonObject map[string]interface{}

type encoder struct {
	short bool
}

func (e encoder) name(f fieldName) string {
	if e.short {
		return f.short
	}
	return f.long
}

// marshalReport encodes metrics report in JSON.
func marshalReport(reportID int64, m *Metrics, short bool) ([]byte, error) {
	e := encoder{short: short}
	report := jsonObject{
		e.name(fieldHeader): jsonObject{
			e.name(fieldReportID): reportID,
			e.name(fieldVersion):  reportVersion,
		},
	}
	metrics := jsonObject{}
	// AWS IoT requires port and connection lists to have at least one entry,
	// so sections with empty lists are omitted.
	if m.ListeningTCPPorts != nil && len(m.ListeningTCPPorts.Ports) > 0 {
		metrics[e.name(fieldListeningTCPPorts)] = e.listeningPorts(m.ListeningTCPPorts)
	}
	if m.ListeningUDPPorts != nil && len(m.ListeningUDPPorts.Ports) > 0 {
		metrics[e.name(fieldListeningUDPPorts)] = e.listeningPorts(m.ListeningUDPPorts)
	}
	if m.NetworkStats != nil {
		metrics[e.name(fieldNetworkStats)] = jsonObject{
			e.name(fieldBytesIn):    m.NetworkStats.BytesIn,
			e.name(fieldBytesOut):   m.NetworkStats.BytesOut,
			e.name(fieldPacketsIn):  m.NetworkStats.PacketsIn,
			e.name(fieldPacketsOut): m.NetworkStats.PacketsOut,
		}
	}
	if m.TCPConnections != nil && len(m.TCPConnections.EstablishedConnections) > 0 {
		metrics[e.name(fieldTCPConnections)] = e.tcpConnections(m.TCPConnections)
	}
	report[e.name(fieldMetrics)] = metrics

	// The custom metrics block is omitted if there are no custom metrics,
	// as AWS IoT Device Defender Agent SDK does.
	if len(m.CustomMetrics) > 0 {
		cm := jsonObject{}
		for name, v := range m.CustomMetrics {
			cm[name] = []jsonObject{{v.kind: v.value}}
		}
		report[e.name(fieldCustomMetrics)] = cm
	}
	return json.Marshal(report)
}

func (e encoder) listeningPorts(lp *ListeningPorts) jsonObject {
	ports := make([]jsonObject, 0, len(lp.Ports))
	for _, p := range lp.Ports {
		o := jsonObject{e.name(fieldPort): p.Port}
		if p.Interface != "" {
			o[e.name(fieldInterface)] = p.Interface
		}
		ports = append(ports, o)
	}
	return jsonObject{
		e.name(fieldPorts): ports,
		e.name(fieldTotal): max(lp.Total, len(lp.Ports)),
	}
}

func (e encoder) tcpConnections(tc *TCPConnections) jsonObject {
	conns := make([]jsonObject, 0, len(tc.EstablishedConnections))
	for _, c := range tc.EstablishedConnections {
		o := jsonObject{
			e.name(fieldRemoteAddr): c.RemoteAddr,
			e.name(fieldLocalPort):  c.LocalPort,
		}
		if c.LocalInterface != "" {
			o[e.name(fieldLocalInterface)] = c.LocalInterface
		}
		conns = append(conns, o)
	}
	return jsonObject{
		e.name(fieldEstablishedConnections): jsonObject{
			e.name(fieldConnections): conns,
			e.name(fieldTotal):       max(tc.Total, len(tc.EstablishedConnections)),
		},
	}
}
