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
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/apache/airavata-custos/signer/internal/httputil"
	"github.com/apache/airavata-custos/signer/internal/metrics"
	"github.com/apache/airavata-custos/signer/internal/store"
)

type RevokeRequest struct {
	SerialNumber  *int64  `json:"serial_number,omitempty"`
	KeyID         *string `json:"key_id,omitempty"`
	CAFingerprint *string `json:"ca_fingerprint,omitempty"`
	Reason        string  `json:"reason"`
}

type RevokeResponse struct {
	Success        bool   `json:"success"`
	Message        string `json:"message"`
	RevokedCount   int    `json:"revoked_count"`
	SerialNumber   int64  `json:"serial_number"`
	Revoked        bool   `json:"revoked"`
	RevokedAt      int64  `json:"revoked_at"`
	Reason         string `json:"reason"`
	AlreadyRevoked bool   `json:"already_revoked,omitempty"`
}

type revocationStore interface {
	RevokeCertificateBySerial(
		ctx context.Context,
		tenantID string,
		clientID string,
		serialNumber int64,
		reason string,
		revokedBy string,
	) (*store.RevokedCertificate, error)
}

type RevokeHandler struct {
	store  revocationStore
	logger *slog.Logger
}

func NewRevokeHandler(store revocationStore, logger *slog.Logger) *RevokeHandler {
	return &RevokeHandler{
		store:  store,
		logger: logger,
	}
}

func (h *RevokeHandler) Handle(w http.ResponseWriter, r *http.Request) {
	clientCfg := httputil.ClientConfigFromContext(r.Context())
	if clientCfg == nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "Missing client config")
		return
	}

	tenantID := clientCfg.TenantID
	clientID := clientCfg.ClientID

	var req RevokeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		metrics.RevokeRequestsTotal.WithLabelValues(tenantID, "error").Inc()
		writeError(w, http.StatusBadRequest, "invalid_request", "Invalid request body")
		return
	}

	if req.SerialNumber == nil || *req.SerialNumber <= 0 {
		metrics.RevokeRequestsTotal.WithLabelValues(tenantID, "error").Inc()
		writeError(w, http.StatusBadRequest, "invalid_request", "Missing or invalid required field: serial_number")
		return
	}

	reason := strings.TrimSpace(req.Reason)
	if reason == "" {
		metrics.RevokeRequestsTotal.WithLabelValues(tenantID, "error").Inc()
		writeError(w, http.StatusBadRequest, "invalid_request", "Missing required field: reason")
		return
	}

	revokedBy := tenantID + ":" + clientID

	revokedCert, err := h.store.RevokeCertificateBySerial(
		r.Context(),
		tenantID,
		clientID,
		*req.SerialNumber,
		reason,
		revokedBy,
	)
	if err != nil {
		metrics.RevokeRequestsTotal.WithLabelValues(tenantID, "error").Inc()

		if errors.Is(err, store.ErrCertificateNotFound) {
			writeError(w, http.StatusNotFound, "not_found", "Certificate not found")
			return
		}

		h.logger.Error("failed to revoke certificate", "error", err, "serial_number", *req.SerialNumber)
		writeError(w, http.StatusInternalServerError, "internal_error", "Failed to revoke certificate")
		return
	}

	metrics.RevokeRequestsTotal.WithLabelValues(tenantID, "success").Inc()

	message := "Certificate revoked successfully"
	if revokedCert.AlreadyRevoked {
		message = "Certificate was already revoked"
	}

	resp := RevokeResponse{
		Success:        true,
		Message:        message,
		RevokedCount:   1,
		SerialNumber:   revokedCert.SerialNumber,
		Revoked:        true,
		RevokedAt:      revokedCert.RevokedAt.Unix(),
		Reason:         revokedCert.Reason,
		AlreadyRevoked: revokedCert.AlreadyRevoked,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)
}
