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
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"time"

	"github.com/at-wat/mqtt-go"
	"github.com/seqsense/aws-iot-device-sdk-go/v6"
)

var envVars = []string{
	"AWS_IOT_ENDPOINT",
	"AWS_IOT_THING_NAME",
	"AWS_IOT_ROOT_CA",
	"AWS_IOT_CERTIFICATE",
	"AWS_IOT_PRIVATE_KEY",
}

func usage() {
	println("usage: mqtt-env")
	println("")
	println("This example connects to AWS IoT, subscribes to THING_NAME/example")
	println("and publishes a message to the same topic.")
	println("THING_NAME must be registered to your account of AWS IoT beforehand.")
	println("")
	println("Following environment variables must be set:")
	println("    AWS_IOT_ENDPOINT: AWS IoT endpoint host name")
	println("  AWS_IOT_THING_NAME: thing name")
	println("     AWS_IOT_ROOT_CA: PEM encoded root CA certificate")
	println(" AWS_IOT_CERTIFICATE: PEM encoded client certificate associated to THING_NAME")
	println(" AWS_IOT_PRIVATE_KEY: PEM encoded private key associated to THING_NAME")
	os.Exit(1)
}

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	env := make(map[string]string)
	for _, name := range envVars {
		v := os.Getenv(name)
		if v == "" {
			println(name, "not set")
			println("")
			usage()
		}
		env[name] = v
	}
	host := env["AWS_IOT_ENDPOINT"]
	thingName := env["AWS_IOT_THING_NAME"]

	certpool := x509.NewCertPool()
	if !certpool.AppendCertsFromPEM([]byte(env["AWS_IOT_ROOT_CA"])) {
		println("failed to parse AWS_IOT_ROOT_CA")
		os.Exit(1)
	}
	cert, err := tls.X509KeyPair(
		[]byte(env["AWS_IOT_CERTIFICATE"]),
		[]byte(env["AWS_IOT_PRIVATE_KEY"]),
	)
	if err != nil {
		panic(err)
	}

	cli, err := awsiotdev.New(
		thingName,
		&mqtt.URLDialer{
			URL: fmt.Sprintf("mqtts://%s:8883", host),
			Options: []mqtt.DialOption{
				mqtt.WithTLSConfig(&tls.Config{
					ServerName:   host,
					RootCAs:      certpool,
					Certificates: []tls.Certificate{cert},
				}),
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

	topic := thingName + "/example"
	received := make(chan struct{})

	cli.Handle(mqtt.HandlerFunc(func(msg *mqtt.Message) {
		fmt.Printf("message received on %s: %s\n", msg.Topic, msg.Payload)
		close(received)
	}))

	if _, err := cli.Connect(ctx,
		thingName,
		mqtt.WithKeepAlive(30),
	); err != nil {
		panic(err)
	}

	fmt.Printf("> subscribe %s\n", topic)
	if _, err := cli.Subscribe(ctx, mqtt.Subscription{Topic: topic, QoS: mqtt.QoS1}); err != nil {
		panic(err)
	}

	fmt.Printf("> publish to %s\n", topic)
	if err := cli.Publish(ctx, &mqtt.Message{
		Topic:   topic,
		QoS:     mqtt.QoS1,
		Payload: []byte(`{"message":"hello from mqtt-env example"}`),
	}); err != nil {
		panic(err)
	}

	select {
	case <-received:
	case <-time.After(10 * time.Second):
		println("timeout waiting for message")
		os.Exit(1)
	}

	if err := cli.Disconnect(ctx); err != nil {
		panic(err)
	}
}
