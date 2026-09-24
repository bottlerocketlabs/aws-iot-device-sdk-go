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
	"context"
	"errors"
	"time"

	"github.com/seqsense/aws-iot-device-sdk-go/v6/internal/ioterr"
)

// DefaultInterval is the default reporting interval of Run.
// AWS IoT throttles reports sent more frequently than once in 5 minutes.
const DefaultInterval = 5 * time.Minute

// Collector collects metrics to be reported.
type Collector interface {
	// Collect returns metrics to be reported.
	// If it returns nil metrics without error, the report is skipped.
	Collect() (*Metrics, error)
}

// CollectorFunc is an adapter to use a function as a Collector.
type CollectorFunc func() (*Metrics, error)

// Collect implements Collector.
func (f CollectorFunc) Collect() (*Metrics, error) {
	return f()
}

// Run collects metrics by c and publishes them by d periodically,
// until ctx is canceled. The first report is sent immediately.
//
// If publishing fails, the same metrics are published again
// as configured by WithRetry. Rejected reports (*ErrorResponse) are not
// retried since the same report would be rejected again.
//
// Errors on collecting or publishing are passed to the handler set by
// WithReportHandler and don't stop the loop.
// Run always returns non-nil error of the context.
func Run(ctx context.Context, d Defender, c Collector, opt ...RunOption) error {
	opts := RunOptions{
		Interval:       DefaultInterval,
		PublishTimeout: 30 * time.Second,
		MaxRetries:     2,
		RetryWait:      10 * time.Second,
	}
	for _, o := range opt {
		o(&opts)
	}

	ticker := time.NewTicker(opts.Interval)
	defer ticker.Stop()

	for {
		m, err := report(ctx, d, c, &opts)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if opts.OnReport != nil && (m != nil || err != nil) {
			opts.OnReport(m, err)
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func report(ctx context.Context, d Defender, c Collector, opts *RunOptions) (*Metrics, error) {
	m, err := c.Collect()
	if err != nil {
		return nil, ioterr.New(err, "collecting metrics")
	}
	if m == nil {
		return nil, nil
	}
	for i := 0; ; i++ {
		err = publish(ctx, d, m, opts.PublishTimeout)
		var er *ErrorResponse
		if err == nil || errors.As(err, &er) || i >= opts.MaxRetries {
			return m, err
		}
		select {
		case <-ctx.Done():
			return m, err
		case <-time.After(opts.RetryWait):
		}
	}
}

func publish(ctx context.Context, d Defender, m *Metrics, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return d.Publish(ctx, m)
}
