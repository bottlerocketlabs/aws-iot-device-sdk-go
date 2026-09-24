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

package main

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/at-wat/mqtt-go"
	"github.com/seqsense/aws-iot-device-sdk-go/v6"
	"github.com/seqsense/aws-iot-device-sdk-go/v6/defender"
	"github.com/seqsense/aws-iot-device-sdk-go/v6/defender/collector"
)

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if len(os.Args) != 3 {
		println("usage: defender AWS_IOT_ENDPOINT THING_NAME")
		println("")
		println("This example collects device-side metrics from Linux procfs")
		println("and reports them to AWS IoT Device Defender every 5 minutes.")
		println("THING_NAME must be registered to your account of AWS IoT beforehand.")
		println("")
		println("If CUSTOM_METRIC_NAME environment variable is set, 1-minute load average")
		println("is reported as a number type custom metric of that name.")
		println("The custom metric must be created in AWS IoT Device Defender beforehand.")
		println("")
		println("Following files must be placed under the current working directory:")
		println("         root-CA.crt: root CA certificate")
		println(" certificate.pem.crt: client certificate associated to THING_NAME")
		println("     private.pem.key: private key associated to THING_NAME")
		os.Exit(1)
	}
	host := os.Args[1]
	thingName := os.Args[2]
	customMetricName := os.Getenv("CUSTOM_METRIC_NAME")

	for _, file := range []string{
		"root-CA.crt",
		"certificate.pem.crt",
		"private.pem.key",
	} {
		_, err := os.Stat(file)
		if os.IsNotExist(err) {
			println(file, "not found")
			os.Exit(1)
		}
	}

	cli, err := awsiotdev.New(
		thingName,
		&mqtt.URLDialer{
			URL: fmt.Sprintf("mqtts://%s:8883", host),
			Options: []mqtt.DialOption{
				mqtt.WithTLSCertFiles(
					host,
					"root-CA.crt",
					"certificate.pem.crt",
					"private.pem.key",
				),
				mqtt.WithConnStateHandler(func(s mqtt.ConnState, err error) {
					fmt.Printf("%s: %v\n", s, err)
				}),
			},
		},
		mqtt.WithReconnectWait(500*time.Millisecond, 2*time.Second),
	)
	if err != nil {
		panic(err)
	}

	// Multiplex message handler to route messages to multiple features.
	var mux mqtt.ServeMux
	cli.Handle(&mux)

	d, err := defender.New(ctx, cli)
	if err != nil {
		panic(err)
	}
	d.OnError(func(err error) {
		fmt.Printf("async error: %v\n", err)
	})
	mux.Handle("#", d) // Handle messages for Device Defender.

	if _, err := cli.Connect(ctx,
		thingName,
		mqtt.WithKeepAlive(30),
	); err != nil {
		panic(err)
	}

	// Wrap the procfs collector to add a custom metric.
	procCollector := collector.New()
	metricsCollector := defender.CollectorFunc(func() (*defender.Metrics, error) {
		m, err := procCollector.Collect()
		if err != nil {
			return nil, err
		}
		if customMetricName != "" {
			load, err := loadAverage()
			if err != nil {
				return nil, err
			}
			m.CustomMetrics = map[string]defender.CustomMetric{
				customMetricName: defender.Number(load),
			}
		}
		return m, nil
	})

	err = defender.Run(ctx, d, metricsCollector,
		defender.WithReportHandler(func(m *defender.Metrics, err error) {
			switch {
			case m == nil:
				fmt.Printf("collect error: %v\n", err)
			case err != nil:
				fmt.Printf("publish error: %v\n", err)
			default:
				fmt.Printf("accepted: %+v\n", *m)
			}
		}),
	)
	panic(err)
}

func loadAverage() (float64, error) {
	b, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return 0, err
	}
	fields := strings.Fields(string(b))
	if len(fields) == 0 {
		return 0, fmt.Errorf("unexpected format: %q", string(b))
	}
	return strconv.ParseFloat(fields[0], 64)
}
