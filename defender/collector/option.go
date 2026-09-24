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

// Options stores Collector options.
type Options struct {
	ProcRoot          string
	MaxListSize       int
	ExcludeInterfaces []string

	interfaceAddrs func() (map[string]string, error)
}

// Option is a functional option of Collector.
type Option func(*Options)

// WithProcRoot sets procfs mount point. Default is /proc.
func WithProcRoot(root string) Option {
	return func(o *Options) {
		o.ProcRoot = root
	}
}

// WithMaxListSize sets maximum number of ports and connections in the report.
// Total count is reported regardless of the limit. Default is 50.
func WithMaxListSize(n int) Option {
	return func(o *Options) {
		o.MaxListSize = n
	}
}

// WithExcludeInterfaces sets interface names excluded from network stats.
// Default is "lo".
func WithExcludeInterfaces(names ...string) Option {
	return func(o *Options) {
		o.ExcludeInterfaces = names
	}
}
