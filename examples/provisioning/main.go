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
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/at-wat/mqtt-go"
	"github.com/seqsense/aws-iot-device-sdk-go/v6"
	"github.com/seqsense/aws-iot-device-sdk-go/v6/provisioning"
)

const credentialsFile = "credentials.json"

// storedCredentials is the format of the runtime credentials saved by
// this example. In production, the private key should be stored securely.
type storedCredentials struct {
	ThingName      string `json:"thingName"`
	CertificatePEM string `json:"certificatePem"`
	PrivateKeyPEM  string `json:"privateKey"`
}

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	flag.Usage = func() {
		println("usage: provisioning AWS_IOT_ENDPOINT TEMPLATE_NAME CLIENT_ID [KEY=VALUE ...]")
		println("")
		println("This example connects to AWS IoT using runtime credentials of the thing.")
		println("If the runtime credentials are not yet saved, the device is provisioned")
		println("by AWS IoT Fleet Provisioning by claim first: it connects as CLIENT_ID")
		println("using the claim certificate, creates a private key and certificate by")
		println("CreateKeysAndCertificate, and registers the thing using TEMPLATE_NAME with")
		println("the given template parameters.")
		println("See provisioning-csr example to keep the private key on the device.")
		println("")
		println("Following files must be placed under the current working directory:")
		println("   root-CA.crt: root CA certificate")
		println(" claim.pem.crt: provisioning claim certificate")
		println(" claim.pem.key: private key of the provisioning claim certificate")
		println("")
		println("Runtime credentials are saved as " + credentialsFile + " and used")
		println("for later connections.")
		os.Exit(1)
	}
	flag.Parse()
	if flag.NArg() < 3 {
		flag.Usage()
	}
	host := flag.Arg(0)
	templateName := flag.Arg(1)
	clientID := flag.Arg(2)

	params := make(map[string]string)
	for _, kv := range flag.Args()[3:] {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			println("invalid parameter:", kv)
			os.Exit(1)
		}
		params[k] = v
	}

	thingName, cert, err := loadCredentials()
	switch {
	case err == nil:
		fmt.Printf("loaded runtime credentials of %s\n", thingName)
	case errors.Is(err, os.ErrNotExist):
		fmt.Print("> provision using claim certificate\n")
		creds, err := provision(ctx, host, templateName, clientID, params)
		if err != nil {
			panic(err)
		}
		fmt.Printf("thing registered: %s, device configuration: %v\n", creds.ThingName, creds.DeviceConfiguration)
		if err := saveCredentials(creds); err != nil {
			panic(err)
		}
		fmt.Printf("saved runtime credentials to %s\n", credentialsFile)
		thingName = creds.ThingName
		if cert, err = creds.TLSCertificate(); err != nil {
			panic(err)
		}
	default:
		panic(err)
	}

	fmt.Print("> connect using runtime credentials\n")
	rootCAs, err := loadRootCAs()
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
					RootCAs:      rootCAs,
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
	// The thing name is typically required as the client ID by the policy
	// attached to the runtime certificate.
	if _, err := cli.Connect(ctx,
		thingName,
		mqtt.WithKeepAlive(30),
	); err != nil {
		panic(err)
	}

	// Use the connection as the thing here, e.g. shadow or jobs.
	fmt.Printf("connected as %s\n", cli.ThingName())

	if err := cli.Disconnect(ctx); err != nil {
		panic(err)
	}
}

// provision connects using the claim certificate and returns runtime
// credentials of the newly registered thing.
// The claim connection is closed before returning.
func provision(ctx context.Context, host, templateName, clientID string, params map[string]string) (*provisioning.Credentials, error) {
	for _, file := range []string{
		"root-CA.crt",
		"claim.pem.crt",
		"claim.pem.key",
	} {
		if _, err := os.Stat(file); err != nil {
			return nil, err
		}
	}

	cli, err := awsiotdev.New(
		clientID,
		&mqtt.URLDialer{
			URL: fmt.Sprintf("mqtts://%s:8883", host),
			Options: []mqtt.DialOption{
				mqtt.WithTLSCertFiles(
					host,
					"root-CA.crt",
					"claim.pem.crt",
					"claim.pem.key",
				),
				mqtt.WithConnStateHandler(func(s mqtt.ConnState, err error) {
					fmt.Printf("claim %s: %v\n", s, err)
				}),
			},
		},
		mqtt.WithReconnectWait(500*time.Millisecond, 2*time.Second),
	)
	if err != nil {
		return nil, err
	}

	p, err := provisioning.New(ctx, cli, templateName)
	if err != nil {
		return nil, err
	}
	p.OnError(func(err error) {
		fmt.Printf("async error: %v\n", err)
	})
	cli.Handle(p)

	if _, err := cli.Connect(ctx,
		clientID,
		mqtt.WithKeepAlive(30),
	); err != nil {
		return nil, err
	}
	defer func() {
		if err := cli.Disconnect(ctx); err != nil {
			fmt.Printf("disconnecting claim connection: %v\n", err)
		}
	}()

	return p.ProvisionWithClaim(ctx, params)
}

func loadCredentials() (string, tls.Certificate, error) {
	b, err := os.ReadFile(credentialsFile)
	if err != nil {
		return "", tls.Certificate{}, err
	}
	var creds storedCredentials
	if err := json.Unmarshal(b, &creds); err != nil {
		return "", tls.Certificate{}, err
	}
	cert, err := tls.X509KeyPair([]byte(creds.CertificatePEM), []byte(creds.PrivateKeyPEM))
	if err != nil {
		return "", tls.Certificate{}, err
	}
	return creds.ThingName, cert, nil
}

// saveCredentials writes the credentials atomically, so that a partially
// written file is not loaded on the next start.
func saveCredentials(creds *provisioning.Credentials) error {
	keyPEM, err := creds.PrivateKeyPEM()
	if err != nil {
		return err
	}
	b, err := json.Marshal(&storedCredentials{
		ThingName:      creds.ThingName,
		CertificatePEM: creds.CertificatePEM,
		PrivateKeyPEM:  keyPEM,
	})
	if err != nil {
		return err
	}
	tmp := credentialsFile + ".tmp"
	if err := os.WriteFile(tmp, b, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, credentialsFile)
}

func loadRootCAs() (*x509.CertPool, error) {
	b, err := os.ReadFile("root-CA.crt")
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(b) {
		return nil, errors.New("no certificate found in root-CA.crt")
	}
	return pool, nil
}
