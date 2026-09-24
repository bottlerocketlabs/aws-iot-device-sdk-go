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

// Package collector collects AWS IoT Device Defender device-side metrics
// from Linux procfs.
package collector

import (
	"errors"
	"net"
	"runtime"
	"sort"
	"strconv"
	"sync"

	"github.com/seqsense/aws-iot-device-sdk-go/v6/defender"
	"github.com/seqsense/aws-iot-device-sdk-go/v6/internal/ioterr"
)

// ErrUnsupported is returned if procfs is not available on the platform.
var ErrUnsupported = errors.New("metrics collection is not supported on this platform")

const defaultProcRoot = "/proc"

var _ defender.Collector = (*Collector)(nil)

// Collector collects device-side metrics.
// It implements defender.Collector.
type Collector struct {
	opts Options
	mu   sync.Mutex
	prev map[string]counters
}

// New creates metrics collector.
func New(opt ...Option) *Collector {
	c := &Collector{
		opts: Options{
			ProcRoot:          defaultProcRoot,
			MaxListSize:       50,
			ExcludeInterfaces: []string{"lo"},
			interfaceAddrs:    interfaceAddrs,
		},
	}
	for _, o := range opt {
		o(&c.opts)
	}
	return c
}

// Collect collects metrics.
// NetworkStats is reported as a difference from the previous Collect call,
// so it is nil on the first call.
func (c *Collector) Collect() (*defender.Metrics, error) {
	if runtime.GOOS != "linux" && c.opts.ProcRoot == defaultProcRoot {
		return nil, ioterr.New(ErrUnsupported, "collecting metrics")
	}

	addrs, err := c.opts.interfaceAddrs()
	if err != nil {
		return nil, ioterr.New(err, "getting interface addresses")
	}
	ifaceName := func(ip net.IP) string {
		if ip.IsUnspecified() {
			return ""
		}
		return addrs[ip.String()]
	}

	tcpSockets, err := readSockets(c.opts.ProcRoot, "tcp", "tcp6")
	if err != nil {
		return nil, err
	}
	var tcpPorts []defender.Port
	var tcpConns []defender.Connection
	for _, s := range tcpSockets {
		switch s.state {
		case tcpListen:
			tcpPorts = append(tcpPorts, defender.Port{
				Port:      s.localPort,
				Interface: ifaceName(s.localIP),
			})
		case tcpEstablished:
			tcpConns = append(tcpConns, defender.Connection{
				RemoteAddr:     net.JoinHostPort(s.remoteIP.String(), strconv.Itoa(s.remotePort)),
				LocalPort:      s.localPort,
				LocalInterface: ifaceName(s.localIP),
			})
		}
	}

	udpSockets, err := readSockets(c.opts.ProcRoot, "udp", "udp6")
	if err != nil {
		return nil, err
	}
	var udpPorts []defender.Port
	for _, s := range udpSockets {
		// Unconnected UDP sockets are in TCP_CLOSE state without remote address.
		if s.state == tcpClose && s.remoteIP.IsUnspecified() {
			udpPorts = append(udpPorts, defender.Port{
				Port:      s.localPort,
				Interface: ifaceName(s.localIP),
			})
		}
	}

	m := &defender.Metrics{
		ListeningTCPPorts: c.listeningPorts(tcpPorts),
		ListeningUDPPorts: c.listeningPorts(udpPorts),
		TCPConnections: &defender.TCPConnections{
			EstablishedConnections: truncate(tcpConns, c.opts.MaxListSize),
			Total:                  len(tcpConns),
		},
	}

	cur, err := readNetDev(c.opts.ProcRoot, c.opts.ExcludeInterfaces)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	if c.prev != nil {
		m.NetworkStats = diffCounters(c.prev, cur)
	}
	c.prev = cur
	c.mu.Unlock()

	return m, nil
}

// listeningPorts returns sorted and deduplicated ports.
func (c *Collector) listeningPorts(ports []defender.Port) *defender.ListeningPorts {
	uniq := make(map[defender.Port]struct{})
	for _, p := range ports {
		uniq[p] = struct{}{}
	}
	ps := make([]defender.Port, 0, len(uniq))
	for p := range uniq {
		ps = append(ps, p)
	}
	sort.Slice(ps, func(i, j int) bool {
		if ps[i].Port != ps[j].Port {
			return ps[i].Port < ps[j].Port
		}
		return ps[i].Interface < ps[j].Interface
	})
	return &defender.ListeningPorts{
		Ports: truncate(ps, c.opts.MaxListSize),
		Total: len(ps),
	}
}

func truncate[T any](s []T, n int) []T {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func diffCounters(prev, cur map[string]counters) *defender.NetworkStats {
	sub := func(c, p uint64) uint64 {
		if c < p {
			// Counter is reset or wrapped around.
			return c
		}
		return c - p
	}
	ns := &defender.NetworkStats{}
	for name, c := range cur {
		p := prev[name]
		ns.BytesIn += sub(c.bytesIn, p.bytesIn)
		ns.BytesOut += sub(c.bytesOut, p.bytesOut)
		ns.PacketsIn += sub(c.packetsIn, p.packetsIn)
		ns.PacketsOut += sub(c.packetsOut, p.packetsOut)
	}
	return ns
}

// interfaceAddrs returns map of IP address to interface name.
func interfaceAddrs() (map[string]string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	ret := make(map[string]string)
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			return nil, err
		}
		for _, addr := range addrs {
			if ipn, ok := addr.(*net.IPNet); ok {
				ret[ipn.IP.String()] = iface.Name
			}
		}
	}
	return ret, nil
}
