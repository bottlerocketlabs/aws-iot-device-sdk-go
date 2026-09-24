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
	"bufio"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/seqsense/aws-iot-device-sdk-go/v6/internal/ioterr"
)

// socketState is a hex-encoded socket state in /proc/net/{tcp,udp}.
// UDP sockets use TCP state values.
type socketState string

// socketState values.
const (
	tcpEstablished socketState = "01"
	tcpClose       socketState = "07"
	tcpListen      socketState = "0A"
)

type socket struct {
	localIP    net.IP
	localPort  int
	remoteIP   net.IP
	remotePort int
	state      socketState
}

type counters struct {
	bytesIn, bytesOut, packetsIn, packetsOut uint64
}

// readSockets reads /proc/net/{tcp,tcp6,udp,udp6} style files.
// Missing files are skipped, e.g. when IPv6 is disabled.
func readSockets(procRoot string, files ...string) ([]socket, error) {
	var ret []socket
	for _, file := range files {
		s, err := readSocketFile(filepath.Join(procRoot, "net", file))
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, ioterr.Newf(err, "reading net/%s", file)
		}
		ret = append(ret, s...)
	}
	return ret, nil
}

func readSocketFile(path string) ([]socket, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var ret []socket
	s := bufio.NewScanner(f)
	s.Scan() // skip header
	for s.Scan() {
		fields := strings.Fields(s.Text())
		if len(fields) < 4 {
			continue
		}
		lip, lport, err := parseAddr(fields[1])
		if err != nil {
			return nil, err
		}
		rip, rport, err := parseAddr(fields[2])
		if err != nil {
			return nil, err
		}
		ret = append(ret, socket{
			localIP:    lip,
			localPort:  lport,
			remoteIP:   rip,
			remotePort: rport,
			state:      socketState(fields[3]),
		})
	}
	if err := s.Err(); err != nil {
		return nil, err
	}
	return ret, nil
}

// parseAddr parses procfs address in "HEXIP:HEXPORT" form.
// IP address is stored as a sequence of 32-bit words in host byte order.
func parseAddr(s string) (net.IP, int, error) {
	hexIP, hexPort, ok := strings.Cut(s, ":")
	if !ok {
		return nil, 0, fmt.Errorf("invalid address: %q", s)
	}
	b, err := hex.DecodeString(hexIP)
	if err != nil || (len(b) != net.IPv4len && len(b) != net.IPv6len) {
		return nil, 0, fmt.Errorf("invalid address: %q", s)
	}
	for i := 0; i < len(b); i += 4 {
		b[i], b[i+1], b[i+2], b[i+3] = b[i+3], b[i+2], b[i+1], b[i]
	}
	port, err := strconv.ParseUint(hexPort, 16, 16)
	if err != nil {
		return nil, 0, fmt.Errorf("invalid port: %q", s)
	}
	return net.IP(b), int(port), nil
}

// readNetDev reads per-interface counters from /proc/net/dev.
func readNetDev(procRoot string, excludeInterfaces []string) (map[string]counters, error) {
	f, err := os.Open(filepath.Join(procRoot, "net", "dev"))
	if err != nil {
		return nil, ioterr.New(err, "opening net/dev")
	}
	defer f.Close()

	exclude := make(map[string]struct{})
	for _, name := range excludeInterfaces {
		exclude[name] = struct{}{}
	}

	ret := make(map[string]counters)
	s := bufio.NewScanner(f)
	for s.Scan() {
		name, stats, ok := strings.Cut(s.Text(), ":")
		if !ok {
			continue // header line
		}
		name = strings.TrimSpace(name)
		if _, ok := exclude[name]; ok {
			continue
		}
		fields := strings.Fields(stats)
		if len(fields) < 10 {
			return nil, ioterr.New(fmt.Errorf("unexpected format: %q", s.Text()), "parsing net/dev")
		}
		var v [4]uint64
		for i, idx := range []int{0, 1, 8, 9} {
			if v[i], err = strconv.ParseUint(fields[idx], 10, 64); err != nil {
				return nil, ioterr.New(err, "parsing net/dev")
			}
		}
		ret[name] = counters{
			bytesIn:    v[0],
			packetsIn:  v[1],
			bytesOut:   v[2],
			packetsOut: v[3],
		}
	}
	if err := s.Err(); err != nil {
		return nil, ioterr.New(err, "reading net/dev")
	}
	return ret, nil
}
