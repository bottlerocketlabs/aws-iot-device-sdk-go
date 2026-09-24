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
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"

	"github.com/seqsense/aws-iot-device-sdk-go/v6/internal/ioterr"
)

// Credentials are the runtime credentials of a provisioned thing.
type Credentials struct {
	ThingName      string
	CertificateID  string
	CertificatePEM string
	// PrivateKey is the key of the certificate.
	// It is the signer given to ProvisionWithCSR, or the key created by
	// AWS IoT on ProvisionWithClaim.
	PrivateKey          crypto.Signer `json:"-"`
	DeviceConfiguration map[string]string
}

// TLSCertificate returns the certificate and private key to be used
// as tls.Config.Certificates.
func (c *Credentials) TLSCertificate() (tls.Certificate, error) {
	var cert tls.Certificate
	rest := []byte(c.CertificatePEM)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			cert.Certificate = append(cert.Certificate, block.Bytes)
		}
	}
	if len(cert.Certificate) == 0 {
		return tls.Certificate{}, ioterr.New(errors.New("no certificate found"), "loading certificate")
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return tls.Certificate{}, ioterr.New(err, "loading certificate")
	}
	if c.PrivateKey == nil {
		return tls.Certificate{}, ioterr.New(errors.New("no private key"), "loading key pair")
	}
	pub, ok := c.PrivateKey.Public().(publicKey)
	if !ok {
		return tls.Certificate{}, ErrUnsupportedKey
	}
	if !pub.Equal(leaf.PublicKey) {
		return tls.Certificate{}, ioterr.New(errors.New("private key does not match certificate"), "loading key pair")
	}
	cert.Leaf = leaf
	cert.PrivateKey = c.PrivateKey
	return cert, nil
}

// PrivateKeyPEM returns the private key as PEM encoded PKCS #8 to be stored
// and reused for later connections. Since it contains the private key, it
// must be stored securely.
// It fails if the key can not be exported, e.g. the key is stored in
// a hardware security module.
func (c *Credentials) PrivateKeyPEM() (string, error) {
	b, err := x509.MarshalPKCS8PrivateKey(c.PrivateKey)
	if err != nil {
		return "", ioterr.New(err, "marshaling private key")
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: b})), nil
}
