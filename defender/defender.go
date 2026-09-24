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

// Package defender implements AWS IoT Device Defender device-side metrics
// reporting.
//
// Note that AWS IoT throttles reports sent more frequently than once
// in 5 minutes.
package defender

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/at-wat/mqtt-go"

	"github.com/seqsense/aws-iot-device-sdk-go/v6"
	"github.com/seqsense/aws-iot-device-sdk-go/v6/internal/ioterr"
)

// Defender is an interface of IoT Device Defender.
type Defender interface {
	mqtt.Handler
	// OnError sets handler of asynchronous errors.
	OnError(func(error))
	// Publish sends metrics report and waits for the response.
	// *ErrorResponse is returned as is if the report is rejected,
	// as jobs.Jobs.UpdateJob does. Other errors are wrapped by ioterr.
	Publish(ctx context.Context, m *Metrics) error
}

type defender struct {
	mqtt.ServeMux
	cli          mqtt.Client
	thingName    string
	mu           sync.Mutex
	chResps      map[int64]chan interface{}
	onError      func(err error)
	lastReportID int64
	opts         Options
}

func (d *defender) topic(operation string) string {
	return "$aws/things/" + d.thingName + "/defender/metrics/json" + operation
}

// New creates IoT Device Defender interface.
func New(ctx context.Context, cli awsiotdev.Device, opt ...Option) (Defender, error) {
	d := &defender{
		cli:       cli,
		thingName: cli.ThingName(),
		chResps:   make(map[int64]chan interface{}),
		opts: Options{
			ReportID: func() int64 { return time.Now().UnixMilli() },
		},
	}
	for _, o := range opt {
		o(&d.opts)
	}

	for _, sub := range []struct {
		topic   string
		handler mqtt.Handler
	}{
		{d.topic("/accepted"), mqtt.HandlerFunc(d.accepted)},
		{d.topic("/rejected"), mqtt.HandlerFunc(d.rejected)},
	} {
		if err := d.ServeMux.Handle(sub.topic, sub.handler); err != nil {
			return nil, ioterr.New(err, "registering message handlers")
		}
	}

	_, err := cli.Subscribe(ctx,
		mqtt.Subscription{Topic: d.topic("/+"), QoS: mqtt.QoS1},
	)
	if err != nil {
		return nil, ioterr.New(err, "subscribing defender topics")
	}
	return d, nil
}

func (d *defender) nextReportID() int64 {
	id := d.opts.ReportID()
	if id <= d.lastReportID {
		id = d.lastReportID + 1
	}
	d.lastReportID = id
	return id
}

func (d *defender) Publish(ctx context.Context, m *Metrics) error {
	ch := make(chan interface{}, 1)
	d.mu.Lock()
	id := d.nextReportID()
	d.chResps[id] = ch
	d.mu.Unlock()
	defer func() {
		d.mu.Lock()
		delete(d.chResps, id)
		d.mu.Unlock()
	}()

	breq, err := marshalReport(id, m, d.opts.ShortNames)
	if err != nil {
		return ioterr.New(err, "marshaling report")
	}
	if err := d.cli.Publish(ctx,
		&mqtt.Message{
			Topic:   d.topic(""),
			QoS:     mqtt.QoS1,
			Payload: breq,
		},
	); err != nil {
		return ioterr.New(err, "sending report")
	}

	select {
	case <-ctx.Done():
		return ioterr.New(ctx.Err(), "publishing metrics")
	case res := <-ch:
		switch r := res.(type) {
		case *Response:
			return nil
		case *ErrorResponse:
			return r
		case error:
			return ioterr.New(r, "publishing metrics")
		default:
			return ioterr.New(ErrInvalidResponse, "publishing metrics")
		}
	}
}

func (d *defender) handleResponse(id int64, r interface{}) {
	d.mu.Lock()
	ch, ok := d.chResps[id]
	d.mu.Unlock()
	if !ok {
		return
	}
	select {
	case ch <- r:
	default:
	}
}

func (d *defender) accepted(msg *mqtt.Message) {
	res := &Response{}
	if err := json.Unmarshal(msg.Payload, res); err != nil {
		d.handleError(ioterr.Newf(err, "unmarshaling accepted response: %s", string(msg.Payload)))
		return
	}
	if res.Status != "" && res.Status != Accepted {
		d.handleResponse(res.ReportID, ioterr.Newf(ErrInvalidResponse, "unexpected status on accepted topic: %s", res.Status))
		return
	}
	d.handleResponse(res.ReportID, res)
}

func (d *defender) rejected(msg *mqtt.Message) {
	e := &ErrorResponse{}
	if err := json.Unmarshal(msg.Payload, e); err != nil {
		d.handleError(ioterr.Newf(err, "unmarshaling error response: %s", string(msg.Payload)))
		return
	}
	d.handleResponse(e.ReportID, e)
}

func (d *defender) OnError(cb func(err error)) {
	d.mu.Lock()
	d.onError = cb
	d.mu.Unlock()
}

func (d *defender) handleError(err error) {
	d.mu.Lock()
	cb := d.onError
	d.mu.Unlock()
	if cb != nil {
		cb(err)
	}
}
