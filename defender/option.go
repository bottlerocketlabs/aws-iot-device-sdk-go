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

import "time"

// Options stores Defender options.
type Options struct {
	ShortNames bool
	ReportID   func() int64
}

// Option is a functional option of Defender.
type Option func(*Options)

// WithShortNames makes the report use short field names
// to reduce the payload size.
func WithShortNames() Option {
	return func(o *Options) {
		o.ShortNames = true
	}
}

// WithReportIDGenerator sets report ID generator.
// Default is current UNIX time in milliseconds.
// Report ID is automatically incremented if the generated value is not
// greater than the previous one, since AWS IoT requires monotonically
// increasing report IDs.
func WithReportIDGenerator(fn func() int64) Option {
	return func(o *Options) {
		o.ReportID = fn
	}
}

// RunOptions stores Run options.
type RunOptions struct {
	Interval       time.Duration
	PublishTimeout time.Duration
	MaxRetries     int
	RetryWait      time.Duration
	OnReport       func(*Metrics, error)
}

// RunOption is a functional option of Run.
type RunOption func(*RunOptions)

// WithInterval sets reporting interval. Default is DefaultInterval.
// Note that AWS IoT throttles reports sent more frequently than once
// in 5 minutes.
func WithInterval(d time.Duration) RunOption {
	return func(o *RunOptions) {
		o.Interval = d
	}
}

// WithPublishTimeout sets timeout of each Publish call. Default is 30 seconds.
func WithPublishTimeout(d time.Duration) RunOption {
	return func(o *RunOptions) {
		o.PublishTimeout = d
	}
}

// WithRetry sets maximum number of retries and wait between them
// when publishing is failed. Default is 2 retries with 10 seconds wait.
// Set maxRetries to 0 to disable retry.
func WithRetry(maxRetries int, wait time.Duration) RunOption {
	return func(o *RunOptions) {
		o.MaxRetries = maxRetries
		o.RetryWait = wait
	}
}

// WithReportHandler sets handler called after each report.
// It is called once per report after retries.
// err is nil if the report is accepted.
// m is nil if collecting metrics is failed.
func WithReportHandler(fn func(m *Metrics, err error)) RunOption {
	return func(o *RunOptions) {
		o.OnReport = fn
	}
}
