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
	"fmt"
)

// Metrics represents device-side metrics to be reported.
// Nil fields, and port/connection lists without entries, are omitted from
// the report since AWS IoT requires the lists to be non-empty.
type Metrics struct {
	ListeningTCPPorts *ListeningPorts
	ListeningUDPPorts *ListeningPorts
	NetworkStats      *NetworkStats
	TCPConnections    *TCPConnections
	CustomMetrics     map[string]CustomMetric
}

// ListeningPorts represents listening TCP or UDP ports.
type ListeningPorts struct {
	Ports []Port
	// Total is the total number of listening ports, which can be larger than
	// the number of Ports if the list is truncated.
	// Values smaller than the number of Ports are replaced by it.
	Total int
}

// Port represents a listening port.
type Port struct {
	Port int
	// Interface is optional name of the interface.
	Interface string
}

// NetworkStats represents network traffic since the last report.
type NetworkStats struct {
	BytesIn    uint64
	BytesOut   uint64
	PacketsIn  uint64
	PacketsOut uint64
}

// TCPConnections represents TCP connections.
type TCPConnections struct {
	EstablishedConnections []Connection
	// Total is the total number of established connections, which can be
	// larger than the number of EstablishedConnections if the list is truncated.
	// Values smaller than the number of EstablishedConnections are replaced by it.
	Total int
}

// Connection represents an established TCP connection.
type Connection struct {
	// RemoteAddr is remote address in "ip:port" form.
	RemoteAddr string
	LocalPort  int
	// LocalInterface is optional name of the local interface.
	LocalInterface string
}

// CustomMetric represents a value of the custom metric.
// Use Number, NumberList, StringList or IPList to create it.
type CustomMetric struct {
	kind  string
	value interface{}
}

// Number creates number type custom metric.
func Number(v float64) CustomMetric {
	return CustomMetric{kind: "number", value: v}
}

// NumberList creates number-list type custom metric.
func NumberList(v ...float64) CustomMetric {
	return CustomMetric{kind: "number_list", value: v}
}

// StringList creates string-list type custom metric.
func StringList(v ...string) CustomMetric {
	return CustomMetric{kind: "string_list", value: v}
}

// IPList creates ip-address-list type custom metric.
func IPList(v ...string) CustomMetric {
	return CustomMetric{kind: "ip_list", value: v}
}

// Status represents status of the metrics report.
type Status string

// Status values.
const (
	Accepted Status = "ACCEPTED"
	Rejected Status = "REJECTED"
)

// StatusDetails represents details of the report status.
type StatusDetails struct {
	ErrorCode    string `json:"ErrorCode"`
	ErrorMessage string `json:"ErrorMessage"`
}

// Response represents response from AWS IoT to the metrics report.
type Response struct {
	ThingName     string        `json:"thingName"`
	ReportID      int64         `json:"reportId"`
	Status        Status        `json:"status"`
	StatusDetails StatusDetails `json:"statusDetails"`
	Timestamp     int64         `json:"timestamp"`
}

// ErrorResponse represents rejected response from AWS IoT.
type ErrorResponse Response

// Error implements error interface.
func (e *ErrorResponse) Error() string {
	return fmt.Sprintf("%s (%d): %s", e.StatusDetails.ErrorCode, e.ReportID, e.StatusDetails.ErrorMessage)
}
