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

package provisioning

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/at-wat/mqtt-go"
	mockmqtt "github.com/at-wat/mqtt-go/mock"

	"github.com/seqsense/aws-iot-device-sdk-go/v6/internal/ioterr"
)

var errPublish = errors.New("publish failure")

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

func TestSubscribe(t *testing.T) {
	testCases := map[string]struct {
		provision func(context.Context, Provisioning) (*Credentials, error)
		expected  []string
	}{
		"ProvisionWithClaim": {
			provision: func(ctx context.Context, p Provisioning) (*Credentials, error) {
				return p.ProvisionWithClaim(ctx, map[string]string{"SerialNumber": "123"})
			},
			expected: []string{
				"$aws/certificates/create/json/accepted",
				"$aws/certificates/create/json/rejected",
				"$aws/provisioning-templates/tmpl/provision/json/accepted",
				"$aws/provisioning-templates/tmpl/provision/json/rejected",
			},
		},
		"ProvisionWithCSR": {
			provision: func(ctx context.Context, p Provisioning) (*Credentials, error) {
				return p.ProvisionWithCSR(ctx, newSigner(t), map[string]string{"SerialNumber": "123"})
			},
			expected: []string{
				"$aws/certificates/create-from-csr/json/accepted",
				"$aws/certificates/create-from-csr/json/rejected",
				"$aws/provisioning-templates/tmpl/provision/json/accepted",
				"$aws/provisioning-templates/tmpl/provision/json/rejected",
			},
		},
	}
	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()

			var topics []string
			p := newMockProvisioning(t, ctx, &mockAWS{
				subscribe: func(subs ...mqtt.Subscription) {
					for _, s := range subs {
						topics = append(topics, s.Topic)
					}
				},
			})
			if len(topics) != 0 {
				t.Fatalf("Expected no subscription on New, got: %v", topics)
			}
			for i := 0; i < 2; i++ {
				if _, err := tc.provision(ctx, p); err != nil {
					t.Fatal(err)
				}
			}
			if !reflect.DeepEqual(tc.expected, topics) {
				t.Errorf("Expected topics: %v, got: %v", tc.expected, topics)
			}
		})
	}

	t.Run("Error", func(t *testing.T) {
		errDummy := errors.New("dummy error")
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()

		var p Provisioning
		var nSubscribe int
		cli := &mockDevice{mockClient: &mockmqtt.Client{
			SubscribeFn: func(ctx context.Context, subs ...mqtt.Subscription) ([]mqtt.Subscription, error) {
				nSubscribe++
				if nSubscribe == 1 {
					return nil, errDummy
				}
				return subs, nil
			},
			PublishFn: func(ctx context.Context, msg *mqtt.Message) error {
				if nSubscribe < 2 {
					t.Error("Unexpected publish before subscription")
				}
				p.Serve(&mqtt.Message{Topic: msg.Topic + "/accepted", Payload: []byte(`{}`)})
				return nil
			},
		}}
		var err error
		p, err = New(ctx, cli, "tmpl")
		if err != nil {
			t.Fatal(err)
		}

		pp := p.(*provisioning)
		_, err = pp.createKeysAndCertificate(ctx)
		var ie *ioterr.Error
		if !errors.As(err, &ie) {
			t.Errorf("Expected error type: %T, got: %T", ie, err)
		}
		if !errors.Is(err, errDummy) {
			t.Errorf("Expected error: %v, got: %v", errDummy, err)
		}

		// Subscription is retried on the next call.
		if _, err := pp.createKeysAndCertificate(ctx); err != nil {
			t.Fatal(err)
		}
		if nSubscribe != 2 {
			t.Errorf("Expected 2 subscribe calls, got: %d", nSubscribe)
		}
	})
}

type testCase struct {
	publishFailure  bool
	noResponse      bool
	expectedTopic   string
	expectedPayload string
	responseTopic   string
	response        string
	expected        interface{}
	errIs           error
	errResponse     *ErrorResponse
	errType         bool
}

func runTestCases(t *testing.T, testCases map[string]testCase, call func(context.Context, *provisioning) (interface{}, error)) {
	t.Helper()
	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()

			var p Provisioning
			cli := &mockDevice{
				mockClient: &mockmqtt.Client{
					PublishFn: func(ctx context.Context, msg *mqtt.Message) error {
						if tc.publishFailure {
							return errPublish
						}
						if msg.Topic != tc.expectedTopic {
							t.Errorf("Expected topic: %s, got: %s", tc.expectedTopic, msg.Topic)
						}
						if string(msg.Payload) != tc.expectedPayload {
							t.Errorf("Expected payload: %s, got: %s", tc.expectedPayload, string(msg.Payload))
						}
						if !tc.noResponse {
							p.Serve(&mqtt.Message{
								Topic:   tc.responseTopic,
								Payload: []byte(tc.response),
							})
						}
						return nil
					},
				},
			}
			var err error
			p, err = New(ctx, cli, "tmpl")
			if err != nil {
				t.Fatal(err)
			}
			p.OnError(func(err error) {
				t.Errorf("Unexpected async error: %v", err)
			})

			res, err := call(ctx, p.(*provisioning))
			switch {
			case tc.errResponse != nil:
				var er *ErrorResponse
				if !errors.As(err, &er) {
					t.Fatalf("Expected error type: %T, got: %v", er, err)
				}
				if !reflect.DeepEqual(tc.errResponse, er) {
					t.Fatalf("Expected error: %v, got: %v", tc.errResponse, er)
				}
			case tc.errIs != nil:
				if !errors.Is(err, tc.errIs) {
					t.Fatalf("Expected error: %v, got: %v", tc.errIs, err)
				}
			case tc.errType:
				var ie *ioterr.Error
				if !errors.As(err, &ie) {
					t.Fatalf("Expected error type: %T, got: %v", ie, err)
				}
			default:
				if err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(tc.expected, res) {
					t.Errorf("Expected: %+v, got: %+v", tc.expected, res)
				}
			}
		})
	}
}

func TestCreateKeysAndCertificate(t *testing.T) {
	const topic = "$aws/certificates/create/json"
	runTestCases(t, map[string]testCase{
		"Success": {
			expectedTopic:   topic,
			expectedPayload: `{}`,
			responseTopic:   topic + "/accepted",
			response:        `{"certificateId":"id","certificatePem":"cert","privateKey":"key","certificateOwnershipToken":"token"}`,
			expected: &createKeysAndCertificateResponse{
				CertificateID:             "id",
				CertificatePEM:            "cert",
				PrivateKey:                "key",
				CertificateOwnershipToken: "token",
			},
		},
		"Rejected": {
			expectedTopic:   topic,
			expectedPayload: `{}`,
			responseTopic:   topic + "/rejected",
			response:        `{"statusCode":403,"errorCode":"Forbidden","errorMessage":"Reason"}`,
			errResponse:     &ErrorResponse{StatusCode: 403, ErrorCode: "Forbidden", ErrorMessage: "Reason"},
		},
		"InvalidResponse": {
			expectedTopic:   topic,
			expectedPayload: `{}`,
			responseTopic:   topic + "/accepted",
			response:        `{"certificateId":1}`,
			errType:         true,
		},
		"PublishError": {
			publishFailure: true,
			errIs:          errPublish,
		},
		"Timeout": {
			expectedTopic:   topic,
			expectedPayload: `{}`,
			noResponse:      true,
			errIs:           context.DeadlineExceeded,
		},
	}, func(ctx context.Context, p *provisioning) (interface{}, error) {
		return p.createKeysAndCertificate(ctx)
	})
}

// newCSR returns a PEM encoded CSR, a PEM encoded certificate and
// the public key of the same key.
func newCSR(t *testing.T) (string, string, publicKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	subject := pkix.Name{CommonName: "test"}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: subject}, key)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	cert, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr})),
		string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert})),
		&key.PublicKey
}

func mustMarshal(t *testing.T, v interface{}) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestCreateCertificateFromCSR(t *testing.T) {
	const topic = "$aws/certificates/create-from-csr/json"
	csr, cert, pub := newCSR(t)
	_, otherCert, _ := newCSR(t)
	req := mustMarshal(t, &createCertificateFromCSRRequest{CertificateSigningRequest: csr})
	res := &createCertificateFromCSRResponse{
		CertificateID:             "id",
		CertificatePEM:            cert,
		CertificateOwnershipToken: "token",
	}
	runTestCases(t, map[string]testCase{
		"Success": {
			expectedTopic:   topic,
			expectedPayload: req,
			responseTopic:   topic + "/accepted",
			response:        mustMarshal(t, res),
			expected:        res,
		},
		"Rejected": {
			expectedTopic:   topic,
			expectedPayload: req,
			responseTopic:   topic + "/rejected",
			response:        `{"statusCode":400,"errorCode":"InvalidCSR","errorMessage":"Reason"}`,
			errResponse:     &ErrorResponse{StatusCode: 400, ErrorCode: "InvalidCSR", ErrorMessage: "Reason"},
		},
		"CertificateMismatch": {
			expectedTopic:   topic,
			expectedPayload: req,
			responseTopic:   topic + "/accepted",
			response: mustMarshal(t, &createCertificateFromCSRResponse{
				CertificateID:             "other",
				CertificatePEM:            otherCert,
				CertificateOwnershipToken: "other",
			}),
			errIs: context.DeadlineExceeded,
		},
		"PublishError": {
			publishFailure: true,
			errIs:          errPublish,
		},
	}, func(ctx context.Context, p *provisioning) (interface{}, error) {
		return p.createCertificateFromCSR(ctx, csr, pub)
	})

	t.Run("StaleResponse", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()

		var p Provisioning
		cli := &mockDevice{mockClient: &mockmqtt.Client{
			PublishFn: func(ctx context.Context, msg *mqtt.Message) error {
				// Response to an earlier timed-out request arrives first.
				go func() {
					p.Serve(&mqtt.Message{
						Topic: topic + "/accepted",
						Payload: []byte(mustMarshal(t, &createCertificateFromCSRResponse{
							CertificateID:  "stale",
							CertificatePEM: otherCert,
						})),
					})
					time.Sleep(10 * time.Millisecond)
					p.Serve(&mqtt.Message{Topic: topic + "/accepted", Payload: []byte(mustMarshal(t, res))})
				}()
				return nil
			},
		}}
		var err error
		p, err = New(ctx, cli, "tmpl")
		if err != nil {
			t.Fatal(err)
		}
		got, err := p.(*provisioning).createCertificateFromCSR(ctx, csr, pub)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(res, got) {
			t.Errorf("Expected: %+v, got: %+v", res, got)
		}
	})
}

func TestRegisterThing(t *testing.T) {
	const topic = "$aws/provisioning-templates/tmpl/provision/json"
	runTestCases(t, map[string]testCase{
		"Success": {
			expectedTopic:   topic,
			expectedPayload: `{"certificateOwnershipToken":"token","parameters":{"SerialNumber":"123"}}`,
			responseTopic:   topic + "/accepted",
			response:        `{"deviceConfiguration":{"key":"val"},"thingName":"thing"}`,
			expected: &registerThingResponse{
				DeviceConfiguration: map[string]string{"key": "val"},
				ThingName:           "thing",
			},
		},
		"Rejected": {
			expectedTopic:   topic,
			expectedPayload: `{"certificateOwnershipToken":"token","parameters":{"SerialNumber":"123"}}`,
			responseTopic:   topic + "/rejected",
			response:        `{"statusCode":400,"errorCode":"InvalidParameters","errorMessage":"Reason"}`,
			errResponse:     &ErrorResponse{StatusCode: 400, ErrorCode: "InvalidParameters", ErrorMessage: "Reason"},
		},
		"InvalidRejected": {
			expectedTopic:   topic,
			expectedPayload: `{"certificateOwnershipToken":"token","parameters":{"SerialNumber":"123"}}`,
			responseTopic:   topic + "/rejected",
			response:        `{"statusCode":"400"}`,
			errType:         true,
		},
	}, func(ctx context.Context, p *provisioning) (interface{}, error) {
		return p.registerThing(ctx, "token", map[string]string{"SerialNumber": "123"})
	})
}

func TestUnexpectedResponse(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	cli := &mockDevice{mockClient: &mockmqtt.Client{}}
	p, err := New(ctx, cli, "tmpl")
	if err != nil {
		t.Fatal(err)
	}

	var asyncErrs []error
	p.OnError(func(err error) {
		asyncErrs = append(asyncErrs, err)
	})

	// Valid response without pending request is silently dropped.
	b, err := json.Marshal(&createKeysAndCertificateResponse{CertificateID: "id"})
	if err != nil {
		t.Fatal(err)
	}
	p.Serve(&mqtt.Message{Topic: "$aws/certificates/create/json/accepted", Payload: b})
	if len(asyncErrs) != 0 {
		t.Fatalf("Unexpected async errors: %v", asyncErrs)
	}

	// Broken response without pending request is reported by OnError.
	p.Serve(&mqtt.Message{Topic: "$aws/certificates/create/json/accepted", Payload: []byte("{")})
	if len(asyncErrs) != 1 {
		t.Fatalf("Expected 1 async error, got: %v", asyncErrs)
	}
	var ie *ioterr.Error
	if !errors.As(asyncErrs[0], &ie) {
		t.Errorf("Expected error type: %T, got: %T", ie, asyncErrs[0])
	}
}

func newSigner(t *testing.T) crypto.Signer {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// newCertificate returns a PEM encoded certificate of pub.
func newCertificate(t *testing.T, pub crypto.PublicKey) string {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	cert, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, newSigner(t))
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert}))
}

var rsaKeyOnce struct {
	sync.Once
	key *rsa.PrivateKey
	err error
}

// rsaKey returns an RSA key shared by the tests since generating it is slow.
func rsaKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	rsaKeyOnce.Do(func() {
		rsaKeyOnce.key, rsaKeyOnce.err = rsa.GenerateKey(rand.Reader, 2048)
	})
	if rsaKeyOnce.err != nil {
		t.Fatal(rsaKeyOnce.err)
	}
	return rsaKeyOnce.key
}

// mockAWS responds to Fleet Provisioning requests like AWS IoT.
type mockAWS struct {
	subscribe func(...mqtt.Subscription)
	// keyPEM overrides the private key returned by CreateKeysAndCertificate.
	keyPEM string
	// registerResponseTopic and registerResponse override the response of
	// RegisterThing.
	registerResponseTopic string
	registerResponse      string

	// Issued certificate and received CSR.
	certPEM string
	csr     *x509.CertificateRequest
}

func newMockProvisioning(t *testing.T, ctx context.Context, m *mockAWS, opts ...Option) Provisioning {
	t.Helper()
	const (
		createTopic   = "$aws/certificates/create/json"
		csrTopic      = "$aws/certificates/create-from-csr/json"
		registerTopic = "$aws/provisioning-templates/tmpl/provision/json"
	)
	var p Provisioning
	cli := &mockDevice{mockClient: &mockmqtt.Client{
		SubscribeFn: func(ctx context.Context, subs ...mqtt.Subscription) ([]mqtt.Subscription, error) {
			if m.subscribe != nil {
				m.subscribe(subs...)
			}
			return subs, nil
		},
		PublishFn: func(ctx context.Context, msg *mqtt.Message) error {
			switch msg.Topic {
			case createTopic:
				// AWS IoT returns a PKCS #1 RSA key.
				key := rsaKey(t)
				m.certPEM = newCertificate(t, &key.PublicKey)
				keyPEM := m.keyPEM
				if keyPEM == "" {
					keyPEM = string(pem.EncodeToMemory(&pem.Block{
						Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key),
					}))
				}
				p.Serve(&mqtt.Message{
					Topic: createTopic + "/accepted",
					Payload: []byte(mustMarshal(t, &createKeysAndCertificateResponse{
						CertificateID:             "id",
						CertificatePEM:            m.certPEM,
						PrivateKey:                keyPEM,
						CertificateOwnershipToken: "token",
					})),
				})
			case csrTopic:
				var req createCertificateFromCSRRequest
				if err := json.Unmarshal(msg.Payload, &req); err != nil {
					t.Fatal(err)
				}
				block, _ := pem.Decode([]byte(req.CertificateSigningRequest))
				if block == nil {
					t.Fatal("Failed to decode CSR")
				}
				csr, err := x509.ParseCertificateRequest(block.Bytes)
				if err != nil {
					t.Fatal(err)
				}
				if err := csr.CheckSignature(); err != nil {
					t.Fatal(err)
				}
				m.csr = csr
				m.certPEM = newCertificate(t, csr.PublicKey)
				p.Serve(&mqtt.Message{
					Topic: csrTopic + "/accepted",
					Payload: []byte(mustMarshal(t, &createCertificateFromCSRResponse{
						CertificateID:             "id",
						CertificatePEM:            m.certPEM,
						CertificateOwnershipToken: "token",
					})),
				})
			case registerTopic:
				expected := `{"certificateOwnershipToken":"token","parameters":{"SerialNumber":"123"}}`
				if string(msg.Payload) != expected {
					t.Errorf("Expected payload: %s, got: %s", expected, string(msg.Payload))
				}
				topic, res := m.registerResponseTopic, m.registerResponse
				if topic == "" {
					topic = registerTopic + "/accepted"
					res = `{"deviceConfiguration":{"key":"val"},"thingName":"thing"}`
				}
				p.Serve(&mqtt.Message{Topic: topic, Payload: []byte(res)})
			default:
				t.Errorf("Unexpected topic: %s", msg.Topic)
			}
			return nil
		},
	}}
	var err error
	p, err = New(ctx, cli, "tmpl", opts...)
	if err != nil {
		t.Fatal(err)
	}
	p.OnError(func(err error) {
		t.Errorf("Unexpected async error: %v", err)
	})
	return p
}

func TestProvision(t *testing.T) {
	params := map[string]string{"SerialNumber": "123"}
	signer := newSigner(t)

	methods := map[string]func(context.Context, Provisioning) (*Credentials, error){
		"ProvisionWithClaim": func(ctx context.Context, p Provisioning) (*Credentials, error) {
			return p.ProvisionWithClaim(ctx, params)
		},
		"ProvisionWithCSR": func(ctx context.Context, p Provisioning) (*Credentials, error) {
			return p.ProvisionWithCSR(ctx, signer, params)
		},
	}

	for name, provision := range methods {
		t.Run(name, func(t *testing.T) {
			t.Run("Success", func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()

				m := &mockAWS{}
				creds, err := provision(ctx, newMockProvisioning(t, ctx, m))
				if err != nil {
					t.Fatal(err)
				}
				if creds.ThingName != "thing" {
					t.Errorf("Expected thing name: thing, got: %s", creds.ThingName)
				}
				if creds.CertificateID != "id" {
					t.Errorf("Expected certificate ID: id, got: %s", creds.CertificateID)
				}
				if creds.CertificatePEM != m.certPEM {
					t.Errorf("Expected certificate: %s, got: %s", m.certPEM, creds.CertificatePEM)
				}
				if !reflect.DeepEqual(map[string]string{"key": "val"}, creds.DeviceConfiguration) {
					t.Errorf("Unexpected device configuration: %v", creds.DeviceConfiguration)
				}
				// Private key must match the issued certificate.
				if _, err := creds.TLSCertificate(); err != nil {
					t.Fatal(err)
				}
			})

			t.Run("RegisterRejected", func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()

				_, err := provision(ctx, newMockProvisioning(t, ctx, &mockAWS{
					registerResponseTopic: "$aws/provisioning-templates/tmpl/provision/json/rejected",
					registerResponse:      `{"statusCode":400,"errorCode":"InvalidParameters","errorMessage":"Reason"}`,
				}))
				var er *ErrorResponse
				if !errors.As(err, &er) {
					t.Fatalf("Expected error type: %T, got: %v", er, err)
				}
				if er.ErrorCode != "InvalidParameters" {
					t.Errorf("Expected error code: InvalidParameters, got: %s", er.ErrorCode)
				}
			})
		})
	}
}

func TestProvisionWithClaim(t *testing.T) {
	t.Run("KeyMismatch", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()

		bkey, err := x509.MarshalPKCS8PrivateKey(newSigner(t))
		if err != nil {
			t.Fatal(err)
		}
		p := newMockProvisioning(t, ctx, &mockAWS{
			keyPEM: string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: bkey})),
		})
		_, err = p.ProvisionWithClaim(ctx, map[string]string{"SerialNumber": "123"})
		var ie *ioterr.Error
		if !errors.As(err, &ie) {
			t.Fatalf("Expected error type: %T, got: %v", ie, err)
		}
	})
}

// unsupportedSigner has a public key without Equal method.
type unsupportedSigner struct {
	crypto.Signer
}

func (unsupportedSigner) Public() crypto.PublicKey {
	return struct{}{}
}

func TestProvisionWithCSR(t *testing.T) {
	params := map[string]string{"SerialNumber": "123"}

	t.Run("Signer", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()

		signer := newSigner(t)
		m := &mockAWS{}
		creds, err := newMockProvisioning(t, ctx, m).ProvisionWithCSR(ctx, signer, params)
		if err != nil {
			t.Fatal(err)
		}
		if creds.PrivateKey != signer {
			t.Error("Expected the given signer as the private key")
		}
		if !signer.Public().(publicKey).Equal(m.csr.PublicKey) {
			t.Error("Expected CSR of the given signer")
		}
	})

	t.Run("CSRTemplate", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()

		m := &mockAWS{}
		p := newMockProvisioning(t, ctx, m, WithCSRTemplate(&x509.CertificateRequest{
			Subject: pkix.Name{CommonName: "device"},
		}))
		if _, err := p.ProvisionWithCSR(ctx, newSigner(t), params); err != nil {
			t.Fatal(err)
		}
		if m.csr.Subject.CommonName != "device" {
			t.Errorf("Expected CSR subject CN: device, got: %s", m.csr.Subject.CommonName)
		}
	})

	t.Run("UnsupportedKey", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()

		p := newMockProvisioning(t, ctx, &mockAWS{})
		_, err := p.ProvisionWithCSR(ctx, unsupportedSigner{}, params)
		if !errors.Is(err, ErrUnsupportedKey) {
			t.Errorf("Expected error: %v, got: %v", ErrUnsupportedKey, err)
		}
	})
}
