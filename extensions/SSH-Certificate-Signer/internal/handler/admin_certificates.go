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
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/go-chi/chi/v5"

	"github.com/apache/airavata-custos/signer/internal/httputil"
	"github.com/apache/airavata-custos/signer/internal/store"
)

type AdminCertificatesHandler struct {
	db     AdminCertificateStore
	logger *slog.Logger
}

type AdminCertificateStore interface {
	ListCertificates(context.Context, int, int) (*store.CertificateListResult, error)
	GetCertificateBySerial(context.Context, int64) (*store.CertificateWithStatus, error)
	RevokeActiveCertificateBySerial(context.Context, int64, string, string) (*store.RevokedCertificate, error)
}

type AdminRevokeRequest struct {
	Reason string `json:"reason"`
}

type AdminRevokeResponse struct {
	Success        bool   `json:"success"`
	Message        string `json:"message"`
	SerialNumber   int64  `json:"serial_number"`
	Revoked        bool   `json:"revoked"`
	RevokedAt      int64  `json:"revoked_at"`
	Reason         string `json:"reason"`
	AlreadyRevoked bool   `json:"already_revoked"`
}

func NewAdminCertificatesHandler(db AdminCertificateStore, logger *slog.Logger) *AdminCertificatesHandler {
	return &AdminCertificatesHandler{db: db, logger: logger}
}

func (h *AdminCertificatesHandler) HandleList(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	if limit <= 0 {
		limit = 20
	}
	if limit > 100 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}

	result, err := h.db.ListCertificates(r.Context(), limit, offset)
	if err != nil {
		h.logger.Error("failed to list certificates for administrator", "error", err)
		writeError(w, http.StatusInternalServerError, "internal_error", "Failed to list certificates")
		return
	}
	certificates := make([]CertificateResponse, 0, len(result.Certificates))
	for i := range result.Certificates {
		certificates = append(certificates, toCertificateResponse(&result.Certificates[i]))
	}
	writeJSON(w, http.StatusOK, CertificateListResponse{
		Certificates: certificates, Total: result.Total, Limit: limit, Offset: offset,
	})
}

func (h *AdminCertificatesHandler) HandleGet(w http.ResponseWriter, r *http.Request) {
	serial, ok := adminSerial(w, r)
	if !ok {
		return
	}
	certificate, err := h.db.GetCertificateBySerial(r.Context(), serial)
	if err != nil {
		if errors.Is(err, store.ErrCertificateNotFound) || strings.Contains(err.Error(), "no rows") {
			writeError(w, http.StatusNotFound, "not_found", "Certificate not found")
			return
		}
		h.logger.Error("failed to get certificate for administrator", "error", err, "serial", serial)
		writeError(w, http.StatusInternalServerError, "internal_error", "Failed to get certificate")
		return
	}
	writeJSON(w, http.StatusOK, toCertificateResponse(certificate))
}

func (h *AdminCertificatesHandler) HandleRevoke(w http.ResponseWriter, r *http.Request) {
	serial, ok := adminSerial(w, r)
	if !ok {
		return
	}
	var request AdminRevokeRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "Invalid request body")
		return
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		writeError(w, http.StatusBadRequest, "invalid_request", "Request body must contain one JSON object")
		return
	}
	reason := strings.TrimSpace(request.Reason)
	if utf8.RuneCountInString(reason) == 0 || utf8.RuneCountInString(reason) > 255 {
		writeError(w, http.StatusBadRequest, "invalid_reason", "Reason must be between 1 and 255 characters")
		return
	}
	caller := httputil.AdminCallerFromContext(r.Context())
	if caller == nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "Missing administrator identity")
		return
	}
	revokedBy := caller.ID
	if revokedBy == "" {
		revokedBy = caller.Email
	}
	result, err := h.db.RevokeActiveCertificateBySerial(r.Context(), serial, reason, revokedBy)
	if errors.Is(err, store.ErrCertificateNotFound) {
		writeError(w, http.StatusNotFound, "not_found", "Certificate not found")
		return
	}
	if errors.Is(err, store.ErrCertificateNotActive) {
		writeError(w, http.StatusConflict, "certificate_not_active", "Certificate is not active")
		return
	}
	if err != nil {
		h.logger.Error("failed to revoke certificate for administrator", "error", err, "serial", serial)
		writeError(w, http.StatusInternalServerError, "internal_error", "Failed to revoke certificate")
		return
	}
	message := "Certificate revoked successfully"
	if result.AlreadyRevoked {
		message = "Certificate was already revoked"
	}
	writeJSON(w, http.StatusOK, AdminRevokeResponse{
		Success: true, Message: message, SerialNumber: result.SerialNumber, Revoked: true,
		RevokedAt: result.RevokedAt.Unix(), Reason: result.Reason, AlreadyRevoked: result.AlreadyRevoked,
	})
}

func adminSerial(w http.ResponseWriter, r *http.Request) (int64, bool) {
	serial, err := strconv.ParseInt(chi.URLParam(r, "serial"), 10, 64)
	if err != nil || serial <= 0 {
		writeError(w, http.StatusBadRequest, "invalid_request", "Invalid serial number")
		return 0, false
	}
	return serial, true
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
