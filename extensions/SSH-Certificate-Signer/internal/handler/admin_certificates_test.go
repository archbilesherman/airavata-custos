// Licensed to the Apache Software Foundation (ASF) under one or more
// contributor license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright ownership.
// The ASF licenses this file to You under the Apache License, Version 2.0.

package handler

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/apache/airavata-custos/signer/internal/httputil"
	"github.com/apache/airavata-custos/signer/internal/store"
)

type adminStoreStub struct {
	list   func(context.Context, int, int) (*store.CertificateListResult, error)
	get    func(context.Context, int64) (*store.CertificateWithStatus, error)
	revoke func(context.Context, int64, string, string) (*store.RevokedCertificate, error)
}

func (s adminStoreStub) ListCertificates(ctx context.Context, limit, offset int) (*store.CertificateListResult, error) {
	return s.list(ctx, limit, offset)
}
func (s adminStoreStub) GetCertificateBySerial(ctx context.Context, serial int64) (*store.CertificateWithStatus, error) {
	return s.get(ctx, serial)
}
func (s adminStoreStub) RevokeActiveCertificateBySerial(ctx context.Context, serial int64, reason, by string) (*store.RevokedCertificate, error) {
	return s.revoke(ctx, serial, reason, by)
}

func testAdminHandler(storeStub adminStoreStub) *AdminCertificatesHandler {
	return NewAdminCertificatesHandler(storeStub, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func TestAdminCertificatesHandleList(t *testing.T) {
	issued := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	handler := testAdminHandler(adminStoreStub{
		list: func(_ context.Context, limit, offset int) (*store.CertificateListResult, error) {
			if limit != 10 || offset != 20 {
				t.Fatalf("pagination = %d/%d", limit, offset)
			}
			return &store.CertificateListResult{Total: 31, Certificates: []store.CertificateWithStatus{{
				TenantID: "tenant-1", ClientID: "client-1", SerialNumber: 42,
				Principal: "alice", UserEmail: "alice@example.org", IssuedAt: issued,
				ValidAfter: issued, ValidBefore: issued.Add(time.Hour),
			}}}, nil
		},
	})
	req := httptest.NewRequest(http.MethodGet, "/?limit=10&offset=20", nil)
	recorder := httptest.NewRecorder()
	handler.HandleList(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", recorder.Code, recorder.Body.String())
	}
	var response CertificateListResponse
	if err := json.NewDecoder(recorder.Body).Decode(&response); err != nil {
		t.Fatal(err)
	}
	if response.Total != 31 || response.Certificates[0].TenantID != "tenant-1" || response.Certificates[0].UserEmail != "alice@example.org" {
		t.Fatalf("unexpected response: %+v", response)
	}
}

func TestAdminCertificatesHandleRevoke(t *testing.T) {
	revokedAt := time.Date(2026, 8, 2, 12, 0, 0, 0, time.UTC)
	handler := testAdminHandler(adminStoreStub{
		revoke: func(_ context.Context, serial int64, reason, by string) (*store.RevokedCertificate, error) {
			if serial != 42 || reason != "compromised key" || by != "admin-1" {
				t.Fatalf("unexpected revoke args: %d %q %q", serial, reason, by)
			}
			return &store.RevokedCertificate{SerialNumber: serial, Reason: reason, RevokedAt: revokedAt}, nil
		},
	})
	router := chi.NewRouter()
	router.Post("/{serial}/revoke", func(w http.ResponseWriter, r *http.Request) {
		ctx := httputil.WithAdminCaller(r.Context(), &httputil.AdminCallerContext{ID: "admin-1"})
		handler.HandleRevoke(w, r.WithContext(ctx))
	})
	req := httptest.NewRequest(http.MethodPost, "/42/revoke", strings.NewReader(`{"reason":"  compromised key  "}`))
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", recorder.Code, recorder.Body.String())
	}
	var response AdminRevokeResponse
	if err := json.NewDecoder(recorder.Body).Decode(&response); err != nil {
		t.Fatal(err)
	}
	if !response.Revoked || response.Reason != "compromised key" || response.AlreadyRevoked {
		t.Fatalf("unexpected response: %+v", response)
	}
}

func TestAdminCertificatesHandleRevokeErrors(t *testing.T) {
	tests := []struct {
		name   string
		body   string
		err    error
		status int
	}{
		{name: "empty reason", body: `{"reason":" "}`, status: http.StatusBadRequest},
		{name: "inactive", body: `{"reason":"expired"}`, err: store.ErrCertificateNotActive, status: http.StatusConflict},
		{name: "not found", body: `{"reason":"missing"}`, err: store.ErrCertificateNotFound, status: http.StatusNotFound},
		{name: "storage", body: `{"reason":"failure"}`, err: errors.New("database down"), status: http.StatusInternalServerError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := testAdminHandler(adminStoreStub{
				revoke: func(context.Context, int64, string, string) (*store.RevokedCertificate, error) {
					return nil, tt.err
				},
			})
			router := chi.NewRouter()
			router.Post("/{serial}/revoke", func(w http.ResponseWriter, r *http.Request) {
				ctx := httputil.WithAdminCaller(r.Context(), &httputil.AdminCallerContext{ID: "admin-1"})
				handler.HandleRevoke(w, r.WithContext(ctx))
			})
			recorder := httptest.NewRecorder()
			router.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/42/revoke", strings.NewReader(tt.body)))
			if recorder.Code != tt.status {
				t.Fatalf("status = %d, want %d body=%s", recorder.Code, tt.status, recorder.Body.String())
			}
		})
	}
}

func TestAdminCertificatesHandleRevokeAlreadyRevoked(t *testing.T) {
	handler := testAdminHandler(adminStoreStub{
		revoke: func(context.Context, int64, string, string) (*store.RevokedCertificate, error) {
			return &store.RevokedCertificate{
				SerialNumber: 42, Reason: "original", RevokedAt: time.Now().UTC(), AlreadyRevoked: true,
			}, nil
		},
	})
	router := chi.NewRouter()
	router.Post("/{serial}/revoke", func(w http.ResponseWriter, r *http.Request) {
		ctx := httputil.WithAdminCaller(r.Context(), &httputil.AdminCallerContext{ID: "admin-1"})
		handler.HandleRevoke(w, r.WithContext(ctx))
	})
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/42/revoke", strings.NewReader(`{"reason":"retry"}`)))
	var response AdminRevokeResponse
	_ = json.NewDecoder(recorder.Body).Decode(&response)
	if recorder.Code != http.StatusOK || !response.AlreadyRevoked || response.Reason != "original" {
		t.Fatalf("status=%d response=%+v", recorder.Code, response)
	}
}
