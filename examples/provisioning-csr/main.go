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
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
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

const (
	deviceKeyFile   = "device.pem.key"
	credentialsFile = "credentials.json"
)

// storedCredentials is the format of the runtime credentials saved by
// this example. The private key is not included since it is kept by the
// signer.
type storedCredentials struct {
	ThingName      string `json:"thingName"`
	CertificatePEM string `json:"certificatePem"`
}

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	flag.Usage = func() {
		println("usage: provisioning-csr AWS_IOT_ENDPOINT TEMPLATE_NAME CLIENT_ID [KEY=VALUE ...]")
		println("")
		println("This example connects to AWS IoT using runtime credentials of the thing.")
		println("If the runtime credentials are not yet saved, the device is provisioned")
		println("by AWS IoT Fleet Provisioning by claim first: it connects as CLIENT_ID")
		println("using the claim certificate, creates a certificate of the device key by")
		println("CreateCertificateFromCSR, and registers the thing using TEMPLATE_NAME with")
		println("the given template parameters.")
		println("The private key never leaves the device. The device key is stored as")
		println(deviceKeyFile + " to simulate a key in a hardware security module, which")
		println("is used through crypto.Signer.")
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

	signer, err := deviceKey()
	if err != nil {
		panic(err)
	}

	creds, err := loadCredentials(signer)
	switch {
	case err == nil:
		fmt.Printf("loaded runtime credentials of %s\n", creds.ThingName)
	case errors.Is(err, os.ErrNotExist):
		fmt.Print("> provision using claim certificate\n")
		creds, err = provision(ctx, host, templateName, clientID, signer, params)
		if err != nil {
			panic(err)
		}
		fmt.Printf("thing registered: %s, device configuration: %v\n", creds.ThingName, creds.DeviceConfiguration)
		if err := saveCredentials(creds); err != nil {
			panic(err)
		}
		fmt.Printf("saved runtime credentials to %s\n", credentialsFile)
	default:
		panic(err)
	}

	fmt.Print("> connect using runtime credentials\n")
	cert, err := creds.TLSCertificate()
	if err != nil {
		panic(err)
	}
	rootCAs, err := loadRootCAs()
	if err != nil {
		panic(err)
	}
	cli, err := awsiotdev.New(
		creds.ThingName,
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
		creds.ThingName,
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
func provision(ctx context.Context, host, templateName, clientID string, signer crypto.Signer, params map[string]string) (*provisioning.Credentials, error) {
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

	return p.ProvisionWithCSR(ctx, signer, params)
}

// deviceKey returns the device key, generating it on the first run.
// In production, a key in a hardware security module can be used instead,
// since only crypto.Signer is required.
func deviceKey() (crypto.Signer, error) {
	b, err := os.ReadFile(deviceKeyFile)
	switch {
	case err == nil:
		block, _ := pem.Decode(b)
		if block == nil {
			return nil, errors.New("no private key found in " + deviceKeyFile)
		}
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		signer, ok := key.(crypto.Signer)
		if !ok {
			return nil, errors.New("unsupported private key in " + deviceKeyFile)
		}
		return signer, nil
	case errors.Is(err, os.ErrNotExist):
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		bkey, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return nil, err
		}
		if err := os.WriteFile(deviceKeyFile,
			pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: bkey}), 0600,
		); err != nil {
			return nil, err
		}
		return key, nil
	default:
		return nil, err
	}
}

func loadCredentials(signer crypto.Signer) (*provisioning.Credentials, error) {
	b, err := os.ReadFile(credentialsFile)
	if err != nil {
		return nil, err
	}
	var creds storedCredentials
	if err := json.Unmarshal(b, &creds); err != nil {
		return nil, err
	}
	return &provisioning.Credentials{
		ThingName:      creds.ThingName,
		CertificatePEM: creds.CertificatePEM,
		PrivateKey:     signer,
	}, nil
}

// saveCredentials writes the credentials atomically, so that a partially
// written file is not loaded on the next start.
func saveCredentials(creds *provisioning.Credentials) error {
	b, err := json.Marshal(&storedCredentials{
		ThingName:      creds.ThingName,
		CertificatePEM: creds.CertificatePEM,
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
