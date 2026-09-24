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
	"crypto/x509"
)

// Options stores Provisioning options.
type Options struct {
	CSRTemplate *x509.CertificateRequest
}

// Option is a functional option of Provisioning.
type Option func(*Options)

// WithCSRTemplate sets the template of the certificate signing request
// created by ProvisionWithCSR, e.g. to set the subject.
// By default, the request has an empty subject.
func WithCSRTemplate(tmpl *x509.CertificateRequest) Option {
	return func(o *Options) {
		o.CSRTemplate = tmpl
	}
}
