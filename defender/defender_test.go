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
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/at-wat/mqtt-go"
	mockmqtt "github.com/at-wat/mqtt-go/mock"

	"github.com/seqsense/aws-iot-device-sdk-go/v6/internal/ioterr"
)

type mockClient interface {
	mqtt.Client
	mqtt.Handler
}

type mockDevice struct {
	mockClient
	mqtt.Retryer
}

func (d *mockDevice) ThingName() string {
	return "test"
}

func TestNew(t *testing.T) {
	errDummy := errors.New("dummy error")

	t.Run("SubscribeError", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()

		cli := &mockDevice{mockClient: &mockmqtt.Client{
			SubscribeFn: func(ctx context.Context, subs ...mqtt.Subscription) ([]mqtt.Subscription, error) {
				return nil, errDummy
			},
		}}
		_, err := New(ctx, cli)
		var ie *ioterr.Error
		if !errors.As(err, &ie) {
			t.Errorf("Expected error type: %T, got: %T", ie, err)
		}
		if !errors.Is(err, errDummy) {
			t.Errorf("Expected error: %v, got: %v", errDummy, err)
		}
	})
	t.Run("Subscriptions", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()

		var topics []string
		cli := &mockDevice{mockClient: &mockmqtt.Client{
			SubscribeFn: func(ctx context.Context, subs ...mqtt.Subscription) ([]mqtt.Subscription, error) {
				for _, s := range subs {
					topics = append(topics, s.Topic)
				}
				return subs, nil
			},
		}}
		if _, err := New(ctx, cli); err != nil {
			t.Fatal(err)
		}
		expected := "$aws/things/test/defender/metrics/json/+"
		if len(topics) != 1 || topics[0] != expected {
			t.Errorf("Expected subscription: [%s], got: %v", expected, topics)
		}
	})
}

func TestPublish(t *testing.T) {
	errDummy := errors.New("dummy error")

	testCases := map[string]struct {
		responseTopic string
		response      interface{}
		publishErr    error
		expectedErr   error
	}{
		"Accepted": {
			responseTopic: "/accepted",
			response: &Response{
				ThingName: "test",
				ReportID:  100,
				Status:    Accepted,
			},
		},
		"Rejected": {
			responseTopic: "/rejected",
			response: &ErrorResponse{
				ThingName: "test",
				ReportID:  100,
				Status:    Rejected,
				StatusDetails: StatusDetails{
					ErrorCode:    "InvalidPayload",
					ErrorMessage: "Malformed metrics report",
				},
			},
			expectedErr: &ErrorResponse{
				ThingName: "test",
				ReportID:  100,
				Status:    Rejected,
				StatusDetails: StatusDetails{
					ErrorCode:    "InvalidPayload",
					ErrorMessage: "Malformed metrics report",
				},
			},
		},
		"UnexpectedStatus": {
			responseTopic: "/accepted",
			response: &Response{
				ReportID: 100,
				Status:   Rejected,
			},
			expectedErr: ErrInvalidResponse,
		},
		"PublishError": {
			publishErr:  errDummy,
			expectedErr: errDummy,
		},
		"Timeout": {
			responseTopic: "/accepted",
			response: &Response{
				ReportID: 99, // unmatched report ID should be ignored
				Status:   Accepted,
			},
			expectedErr: context.DeadlineExceeded,
		},
	}

	for name, testCase := range testCases {
		testCase := testCase
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
			defer cancel()

			var cli *mockDevice
			var d Defender
			cli = &mockDevice{mockClient: &mockmqtt.Client{
				PublishFn: func(ctx context.Context, msg *mqtt.Message) error {
					if testCase.publishErr != nil {
						return testCase.publishErr
					}
					if msg.Topic != "$aws/things/test/defender/metrics/json" {
						t.Errorf("Unexpected topic: %s", msg.Topic)
					}
					if msg.QoS != mqtt.QoS1 {
						t.Errorf("Expected QoS1, got: %v", msg.QoS)
					}
					res, err := json.Marshal(testCase.response)
					if err != nil {
						t.Fatal(err)
					}
					go cli.Serve(&mqtt.Message{
						Topic:   d.(*defender).topic(testCase.responseTopic),
						Payload: res,
					})
					return nil
				},
			}}
			var err error
			d, err = New(ctx, cli, WithReportIDGenerator(func() int64 { return 100 }))
			if err != nil {
				t.Fatal(err)
			}
			cli.Handle(d)

			err = d.Publish(ctx, &Metrics{})
			if testCase.expectedErr == nil {
				if err != nil {
					t.Fatalf("Unexpected error: %v", err)
				}
				return
			}
			var er *ErrorResponse
			if errors.As(testCase.expectedErr, &er) {
				var got *ErrorResponse
				if !errors.As(err, &got) {
					t.Fatalf("Expected error type: %T, got: %T", er, err)
				}
				if *got != *er {
					t.Errorf("Expected error: %+v, got: %+v", *er, *got)
				}
				return
			}
			if !errors.Is(err, testCase.expectedErr) {
				t.Errorf("Expected error: %v, got: %v", testCase.expectedErr, err)
			}
		})
	}
}

func TestReportID(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	var ids []int64
	var cli *mockDevice
	cli = &mockDevice{mockClient: &mockmqtt.Client{
		PublishFn: func(ctx context.Context, msg *mqtt.Message) error {
			r := struct {
				Header struct {
					ReportID int64 `json:"report_id"`
				} `json:"header"`
			}{}
			if err := json.Unmarshal(msg.Payload, &r); err != nil {
				t.Fatal(err)
			}
			ids = append(ids, r.Header.ReportID)
			res, err := json.Marshal(&Response{ReportID: r.Header.ReportID, Status: Accepted})
			if err != nil {
				t.Fatal(err)
			}
			go cli.Serve(&mqtt.Message{
				Topic:   "$aws/things/test/defender/metrics/json/accepted",
				Payload: res,
			})
			return nil
		},
	}}
	gen := []int64{10, 10, 5, 20}
	d, err := New(ctx, cli, WithReportIDGenerator(func() int64 {
		id := gen[0]
		gen = gen[1:]
		return id
	}))
	if err != nil {
		t.Fatal(err)
	}
	cli.Handle(d)

	for i := 0; i < 4; i++ {
		if err := d.Publish(ctx, &Metrics{}); err != nil {
			t.Fatal(err)
		}
	}
	expected := []int64{10, 11, 12, 20}
	if len(ids) != len(expected) {
		t.Fatalf("Expected report IDs: %v, got: %v", expected, ids)
	}
	for i := range expected {
		if ids[i] != expected[i] {
			t.Fatalf("Expected report IDs: %v, got: %v", expected, ids)
		}
	}
}

func TestInvalidResponse(t *testing.T) {
	for _, topic := range []string{"/accepted", "/rejected"} {
		topic := topic
		t.Run(topic, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()

			cli := &mockDevice{mockClient: &mockmqtt.Client{}}
			d, err := New(ctx, cli)
			if err != nil {
				t.Fatal(err)
			}
			cli.Handle(d)

			chErr := make(chan error, 1)
			d.OnError(func(err error) { chErr <- err })

			cli.Serve(&mqtt.Message{
				Topic:   d.(*defender).topic(topic),
				Payload: []byte("{"),
			})

			select {
			case err := <-chErr:
				var ie *ioterr.Error
				if !errors.As(err, &ie) {
					t.Errorf("Expected error type: %T, got: %T", ie, err)
				}
			case <-ctx.Done():
				t.Fatal("Timeout")
			}
		})
	}
}
