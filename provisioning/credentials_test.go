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
	"testing"
)

// hsmSigner is a signer whose private key can not be exported.
type hsmSigner struct {
	crypto.Signer
}

func TestCredentialsTLSCertificate(t *testing.T) {
	signer := newSigner(t)
	certPEM := newCertificate(t, signer.Public())

	t.Run("Success", func(t *testing.T) {
		creds := &Credentials{CertificatePEM: certPEM, PrivateKey: hsmSigner{signer}}
		cert, err := creds.TLSCertificate()
		if err != nil {
			t.Fatal(err)
		}
		if cert.PrivateKey != creds.PrivateKey {
			t.Error("Expected the signer as the private key")
		}
		if cert.Leaf == nil || len(cert.Certificate) != 1 {
			t.Errorf("Unexpected certificate: %+v", cert)
		}
	})

	for name, creds := range map[string]*Credentials{
		"NoCertificate": {CertificatePEM: "invalid", PrivateKey: signer},
		"NoPrivateKey":  {CertificatePEM: certPEM},
		"KeyMismatch":   {CertificatePEM: certPEM, PrivateKey: newSigner(t)},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := creds.TLSCertificate(); err == nil {
				t.Error("Expected error")
			}
		})
	}
}

func TestCredentialsPrivateKeyPEM(t *testing.T) {
	signer := newSigner(t)
	certPEM := newCertificate(t, signer.Public())

	t.Run("Success", func(t *testing.T) {
		creds := &Credentials{CertificatePEM: certPEM, PrivateKey: signer}
		keyPEM, err := creds.PrivateKeyPEM()
		if err != nil {
			t.Fatal(err)
		}
		// Stored key can be loaded as the key of the certificate.
		if _, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM)); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("NotExportable", func(t *testing.T) {
		creds := &Credentials{CertificatePEM: certPEM, PrivateKey: hsmSigner{signer}}
		if _, err := creds.PrivateKeyPEM(); err == nil {
			t.Error("Expected error")
		}
	})
}
