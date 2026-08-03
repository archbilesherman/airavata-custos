// Licensed to the Apache Software Foundation (ASF) under one or more
// contributor license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright ownership.
// The ASF licenses this file to You under the Apache License, Version 2.0.

package store

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
)

func certificateQueryRow() *sqlmock.Rows {
	issued := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	revoked := issued.Add(30 * time.Minute)
	return sqlmock.NewRows([]string{
		"id", "tenant_id", "client_id", "serial_number", "key_id", "principal", "user_email",
		"public_key_fingerprint", "ca_fingerprint", "valid_after", "valid_before", "issued_at",
		"source_ip", "granted_extensions", "force_command", "revoked", "revoked_at", "revocation_reason", "revoked_by",
	}).AddRow(
		1, "tenant-1", "client-1", 42, "key-1", "alice", "alice@example.org",
		"SHA256:key", "SHA256:ca", issued, issued.Add(time.Hour), issued,
		"192.0.2.1", []byte(`["permit-pty"]`), nil, true, revoked, "compromised", "admin@example.org",
	)
}

func TestListCertificatesDeploymentWide(t *testing.T) {
	db, mock := newMockDB(t)
	mock.ExpectQuery("SELECT COUNT\\(\\*\\) FROM certificate_issuance_logs").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))
	mock.ExpectQuery("LEFT JOIN revocation_events r ON r.id").
		WithArgs(20, 0).
		WillReturnRows(certificateQueryRow())

	result, err := db.ListCertificates(context.Background(), 0, -1)
	if err != nil {
		t.Fatal(err)
	}
	if result.Total != 1 || len(result.Certificates) != 1 {
		t.Fatalf("unexpected result: %+v", result)
	}
	certificate := result.Certificates[0]
	if certificate.TenantID != "tenant-1" || certificate.UserEmail != "alice@example.org" || !certificate.Revoked {
		t.Fatalf("unexpected certificate: %+v", certificate)
	}
	if certificate.RevokedBy != "admin@example.org" {
		t.Fatalf("unexpected revocation actor: %q", certificate.RevokedBy)
	}
	if len(certificate.GrantedExtensions) != 1 || certificate.GrantedExtensions[0] != "permit-pty" {
		t.Fatalf("unexpected extensions: %v", certificate.GrantedExtensions)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestGetCertificateBySerialMapsNotFound(t *testing.T) {
	db, mock := newMockDB(t)
	mock.ExpectQuery("FROM certificate_issuance_logs c").WithArgs(int64(99)).WillReturnError(sql.ErrNoRows)
	_, err := db.GetCertificateBySerial(context.Background(), 99)
	if !errors.Is(err, ErrCertificateNotFound) {
		t.Fatalf("error = %v, want ErrCertificateNotFound", err)
	}
}
