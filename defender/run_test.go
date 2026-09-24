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
	"testing"
	"time"

	"github.com/at-wat/mqtt-go"
)

type mockDefender struct {
	PublishFn func(ctx context.Context, m *Metrics) error
}

func (d *mockDefender) Serve(*mqtt.Message) {}
func (d *mockDefender) OnError(func(error)) {}
func (d *mockDefender) Publish(ctx context.Context, m *Metrics) error {
	return d.PublishFn(ctx, m)
}

type result struct {
	m   *Metrics
	err error
}

func TestRun(t *testing.T) {
	errCollect := errors.New("collect error")
	errPublish := errors.New("publish error")

	t.Run("Periodic", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()

		// Collect: error, nil (skipped), metrics, metrics (publish error), ...
		n := 0
		c := CollectorFunc(func() (*Metrics, error) {
			n++
			switch n {
			case 1:
				return nil, errCollect
			case 2:
				return nil, nil
			default:
				return &Metrics{}, nil
			}
		})
		published := 0
		d := &mockDefender{PublishFn: func(ctx context.Context, m *Metrics) error {
			published++
			if published == 2 {
				return errPublish
			}
			return nil
		}}

		var results []result
		err := Run(ctx, d, c,
			WithInterval(10*time.Millisecond),
			WithRetry(0, 0),
			WithReportHandler(func(m *Metrics, err error) {
				results = append(results, result{m, err})
				if len(results) == 3 {
					cancel()
				}
			}),
		)
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Expected error: %v, got: %v", context.Canceled, err)
		}
		if len(results) != 3 {
			t.Fatalf("Expected 3 reports, got: %v", results)
		}
		if results[0].m != nil || !errors.Is(results[0].err, errCollect) {
			t.Errorf("Expected collect error, got: %+v", results[0])
		}
		if results[1].m == nil || results[1].err != nil {
			t.Errorf("Expected accepted report, got: %+v", results[1])
		}
		if results[2].m == nil || !errors.Is(results[2].err, errPublish) {
			t.Errorf("Expected publish error, got: %+v", results[2])
		}
		if n != 4 {
			t.Errorf("Expected 4 collections, got: %d", n)
		}
	})

	t.Run("Retry", func(t *testing.T) {
		errRejected := &ErrorResponse{Status: Rejected}

		testCases := map[string]struct {
			errs              []error
			expectedPublishes int
			expectedErr       error
		}{
			"SucceedAfterRetry": {
				errs:              []error{errPublish, errPublish, nil},
				expectedPublishes: 3,
			},
			"RetryExhausted": {
				errs:              []error{errPublish, errPublish, errPublish, nil},
				expectedPublishes: 3,
				expectedErr:       errPublish,
			},
			"RejectedNotRetried": {
				errs:              []error{errRejected, nil},
				expectedPublishes: 1,
				expectedErr:       errRejected,
			},
		}
		for name, testCase := range testCases {
			testCase := testCase
			t.Run(name, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()

				var collected []*Metrics
				c := CollectorFunc(func() (*Metrics, error) {
					m := &Metrics{}
					collected = append(collected, m)
					return m, nil
				})
				var published []*Metrics
				d := &mockDefender{PublishFn: func(ctx context.Context, m *Metrics) error {
					published = append(published, m)
					return testCase.errs[len(published)-1]
				}}

				var res result
				err := Run(ctx, d, c,
					WithRetry(2, time.Millisecond),
					WithReportHandler(func(m *Metrics, err error) {
						res = result{m, err}
						cancel()
					}),
				)
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("Expected error: %v, got: %v", context.Canceled, err)
				}
				if len(collected) != 1 {
					t.Fatalf("Expected 1 collection, got: %d", len(collected))
				}
				if len(published) != testCase.expectedPublishes {
					t.Fatalf("Expected %d publishes, got: %d", testCase.expectedPublishes, len(published))
				}
				for _, m := range published {
					if m != collected[0] {
						t.Error("Retry must publish the same metrics")
					}
				}
				if !errors.Is(res.err, testCase.expectedErr) {
					t.Errorf("Expected error: %v, got: %v", testCase.expectedErr, res.err)
				}
			})
		}
	})

	t.Run("PublishTimeout", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()

		c := CollectorFunc(func() (*Metrics, error) { return &Metrics{}, nil })
		d := &mockDefender{PublishFn: func(ctx context.Context, m *Metrics) error {
			<-ctx.Done()
			return ctx.Err()
		}}

		chErr := make(chan error, 1)
		go Run(ctx, d, c,
			WithPublishTimeout(10*time.Millisecond),
			WithRetry(0, 0),
			WithReportHandler(func(m *Metrics, err error) {
				chErr <- err
			}),
		)
		select {
		case err := <-chErr:
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Errorf("Expected error: %v, got: %v", context.DeadlineExceeded, err)
			}
		case <-ctx.Done():
			t.Fatal("Timeout")
		}
	})

	t.Run("CancelDuringPublish", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		c := CollectorFunc(func() (*Metrics, error) { return &Metrics{}, nil })
		d := &mockDefender{PublishFn: func(ctx context.Context, m *Metrics) error {
			cancel()
			<-ctx.Done()
			return ctx.Err()
		}}

		err := Run(ctx, d, c, WithReportHandler(func(m *Metrics, err error) {
			t.Errorf("Handler must not be called on cancel, got: %v", err)
		}))
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Expected error: %v, got: %v", context.Canceled, err)
		}
	})
}
