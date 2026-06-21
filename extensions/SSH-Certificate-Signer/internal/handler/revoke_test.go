// Licensed to the Apache Software Foundation (ASF) under one or more
// contributor license agreements.  See the NOTICE file distributed with
// this work for additional information regarding copyright ownership.
// The ASF licenses this file to You under the Apache License, Version 2.0
// (the "License"); you may not use this file except in compliance with
// the License.  You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/apache/airavata-custos/signer/internal/httputil"
	"github.com/apache/airavata-custos/signer/internal/store"
)

type fakeRevocationStore struct {
	result *store.RevokedCertificate
	err    error

	gotTenantID     string
	gotClientID     string
	gotSerialNumber int64
	gotReason       string
	gotRevokedBy    string
}

func (f *fakeRevocationStore) RevokeCertificateBySerial(
	ctx context.Context,
	tenantID string,
	clientID string,
	serialNumber int64,
	reason string,
	revokedBy string,
) (*store.RevokedCertificate, error) {
	f.gotTenantID = tenantID
	f.gotClientID = clientID
	f.gotSerialNumber = serialNumber
	f.gotReason = reason
	f.gotRevokedBy = revokedBy

	return f.result, f.err
}

func newTestRevokeHandler(fake *fakeRevocationStore) *RevokeHandler {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	return NewRevokeHandler(fake, logger)
}

func newRevokeRequest(body string, withClient bool) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/revoke", bytes.NewBufferString(body))

	if withClient {
		cfg := &store.ClientConfig{
			TenantID: "tenant1",
			ClientID: "webapp",
		}
		req = req.WithContext(httputil.WithClientConfig(req.Context(), cfg))
	}

	return req
}

func decodeRevokeResponse(t *testing.T, rr *httptest.ResponseRecorder) RevokeResponse {
	t.Helper()

	var resp RevokeResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v\nbody: %s", err, rr.Body.String())
	}

	return resp
}

func decodeErrorResponse(t *testing.T, rr *httptest.ResponseRecorder) map[string]string {
	t.Helper()

	var resp map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode error response: %v\nbody: %s", err, rr.Body.String())
	}

	return resp
}

func TestRevokeHandler_Success(t *testing.T) {
	revokedAt := time.Unix(1700000000, 0).UTC()

	fake := &fakeRevocationStore{
		result: &store.RevokedCertificate{
			SerialNumber:   3,
			KeyID:          "key-3",
			CAFingerprint:  "SHA256:test",
			Reason:         "Testing revoke",
			RevokedAt:      revokedAt,
			AlreadyRevoked: false,
		},
	}

	handler := newTestRevokeHandler(fake)
	req := newRevokeRequest(`{"serial_number":3,"reason":"Testing revoke"}`, true)
	rr := httptest.NewRecorder()

	handler.Handle(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", rr.Code, rr.Body.String())
	}

	resp := decodeRevokeResponse(t, rr)

	if !resp.Success {
		t.Fatal("expected success true")
	}
	if !resp.Revoked {
		t.Fatal("expected revoked true")
	}
	if resp.SerialNumber != 3 {
		t.Fatalf("expected serial 3, got %d", resp.SerialNumber)
	}
	if resp.Reason != "Testing revoke" {
		t.Fatalf("expected reason to round trip, got %q", resp.Reason)
	}
	if resp.AlreadyRevoked {
		t.Fatal("expected already_revoked false")
	}

	if fake.gotTenantID != "tenant1" || fake.gotClientID != "webapp" {
		t.Fatalf("wrong client context: %s:%s", fake.gotTenantID, fake.gotClientID)
	}
	if fake.gotRevokedBy != "tenant1:webapp" {
		t.Fatalf("wrong revoked_by: %s", fake.gotRevokedBy)
	}
}

func TestRevokeHandler_AlreadyRevoked(t *testing.T) {
	revokedAt := time.Unix(1700000000, 0).UTC()

	fake := &fakeRevocationStore{
		result: &store.RevokedCertificate{
			SerialNumber:   3,
			KeyID:          "key-3",
			CAFingerprint:  "SHA256:test",
			Reason:         "Already revoked reason",
			RevokedAt:      revokedAt,
			AlreadyRevoked: true,
		},
	}

	handler := newTestRevokeHandler(fake)
	req := newRevokeRequest(`{"serial_number":3,"reason":"Testing revoke again"}`, true)
	rr := httptest.NewRecorder()

	handler.Handle(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", rr.Code, rr.Body.String())
	}

	resp := decodeRevokeResponse(t, rr)

	if !resp.Success || !resp.Revoked {
		t.Fatalf("expected successful revoked response: %+v", resp)
	}
	if !resp.AlreadyRevoked {
		t.Fatal("expected already_revoked true")
	}
}

func TestRevokeHandler_MissingSerial(t *testing.T) {
	fake := &fakeRevocationStore{}
	handler := newTestRevokeHandler(fake)
	req := newRevokeRequest(`{"reason":"missing serial"}`, true)
	rr := httptest.NewRecorder()

	handler.Handle(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}

	resp := decodeErrorResponse(t, rr)
	if resp["error"] != "invalid_request" {
		t.Fatalf("expected invalid_request, got %+v", resp)
	}
}

func TestRevokeHandler_InvalidSerial(t *testing.T) {
	fake := &fakeRevocationStore{}
	handler := newTestRevokeHandler(fake)
	req := newRevokeRequest(`{"serial_number":0,"reason":"bad serial"}`, true)
	rr := httptest.NewRecorder()

	handler.Handle(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}
}

func TestRevokeHandler_MissingReason(t *testing.T) {
	fake := &fakeRevocationStore{}
	handler := newTestRevokeHandler(fake)
	req := newRevokeRequest(`{"serial_number":3}`, true)
	rr := httptest.NewRecorder()

	handler.Handle(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}
}

func TestRevokeHandler_MalformedJSON(t *testing.T) {
	fake := &fakeRevocationStore{}
	handler := newTestRevokeHandler(fake)
	req := newRevokeRequest(`{`, true)
	rr := httptest.NewRecorder()

	handler.Handle(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}

	resp := decodeErrorResponse(t, rr)
	if resp["error"] != "invalid_request" {
		t.Fatalf("expected invalid_request, got %+v", resp)
	}
}

func TestRevokeHandler_UnknownSerial(t *testing.T) {
	fake := &fakeRevocationStore{
		err: store.ErrCertificateNotFound,
	}

	handler := newTestRevokeHandler(fake)
	req := newRevokeRequest(`{"serial_number":999,"reason":"unknown serial"}`, true)
	rr := httptest.NewRecorder()

	handler.Handle(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", rr.Code, rr.Body.String())
	}

	resp := decodeErrorResponse(t, rr)
	if resp["error"] != "not_found" {
		t.Fatalf("expected not_found, got %+v", resp)
	}
}

func TestRevokeHandler_InternalStoreError(t *testing.T) {
	fake := &fakeRevocationStore{
		err: errors.New("database down"),
	}

	handler := newTestRevokeHandler(fake)
	req := newRevokeRequest(`{"serial_number":3,"reason":"store error"}`, true)
	rr := httptest.NewRecorder()

	handler.Handle(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", rr.Code)
	}

	resp := decodeErrorResponse(t, rr)
	if resp["error"] != "internal_error" {
		t.Fatalf("expected internal_error, got %+v", resp)
	}
}

func TestRevokeHandler_MissingClientConfig(t *testing.T) {
	fake := &fakeRevocationStore{}
	handler := newTestRevokeHandler(fake)
	req := newRevokeRequest(`{"serial_number":3,"reason":"no client"}`, false)
	rr := httptest.NewRecorder()

	handler.Handle(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", rr.Code)
	}

	resp := decodeErrorResponse(t, rr)
	if resp["error"] != "internal_error" {
		t.Fatalf("expected internal_error, got %+v", resp)
	}
}
