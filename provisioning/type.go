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
	"fmt"
)

type createKeysAndCertificateResponse struct {
	CertificateID             string `json:"certificateId"`
	CertificatePEM            string `json:"certificatePem"`
	PrivateKey                string `json:"privateKey"`
	CertificateOwnershipToken string `json:"certificateOwnershipToken"`
}

type createCertificateFromCSRResponse struct {
	CertificateID             string `json:"certificateId"`
	CertificatePEM            string `json:"certificatePem"`
	CertificateOwnershipToken string `json:"certificateOwnershipToken"`
}

type registerThingResponse struct {
	DeviceConfiguration map[string]string `json:"deviceConfiguration"`
	ThingName           string            `json:"thingName"`
}

// ErrorResponse represents error message from AWS IoT.
type ErrorResponse struct {
	StatusCode   int    `json:"statusCode"`
	ErrorCode    string `json:"errorCode"`
	ErrorMessage string `json:"errorMessage"`
}

// Error implements error interface.
func (e *ErrorResponse) Error() string {
	return fmt.Sprintf("%s (%d): %s", e.ErrorCode, e.StatusCode, e.ErrorMessage)
}

type createCertificateFromCSRRequest struct {
	CertificateSigningRequest string `json:"certificateSigningRequest"`
}

type registerThingRequest struct {
	CertificateOwnershipToken string            `json:"certificateOwnershipToken"`
	Parameters                map[string]string `json:"parameters,omitempty"`
}
