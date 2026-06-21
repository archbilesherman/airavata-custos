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

package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

var ErrCertificateNotFound = errors.New("certificate not found")

type RevocationEvent struct {
	TenantID      string
	ClientID      string
	SerialNumber  *int64
	KeyID         *string
	CAFingerprint *string
	Reason        string
	RevokedBy     string
}

type RevokedCertificate struct {
	SerialNumber   int64
	KeyID          string
	CAFingerprint  string
	Reason         string
	RevokedAt      time.Time
	AlreadyRevoked bool
}

func (d *DB) InsertRevocationEvent(ctx context.Context, ev *RevocationEvent) error {
	var serialNumber sql.NullInt64
	if ev.SerialNumber != nil {
		serialNumber = sql.NullInt64{Int64: *ev.SerialNumber, Valid: true}
	}

	var keyID sql.NullString
	if ev.KeyID != nil {
		keyID = sql.NullString{String: *ev.KeyID, Valid: true}
	}

	var caFingerprint sql.NullString
	if ev.CAFingerprint != nil {
		caFingerprint = sql.NullString{String: *ev.CAFingerprint, Valid: true}
	}

	_, err := d.ExecContext(ctx,
		`INSERT INTO revocation_events
			(tenant_id, client_id, serial_number, key_id, ca_fingerprint, reason, revoked_by)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		ev.TenantID, ev.ClientID, serialNumber, keyID, caFingerprint, ev.Reason, ev.RevokedBy,
	)
	if err != nil {
		return fmt.Errorf("inserting revocation event: %w", err)
	}

	return nil
}

func (d *DB) RevokeCertificateBySerial(
	ctx context.Context,
	tenantID string,
	clientID string,
	serialNumber int64,
	reason string,
	revokedBy string,
) (*RevokedCertificate, error) {
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin revoke transaction: %w", err)
	}
	defer tx.Rollback()

	var keyID string
	var caFingerprint string

	err = tx.QueryRowContext(ctx,
		`SELECT key_id, ca_fingerprint
		   FROM certificate_issuance_logs
		  WHERE tenant_id = ?
		    AND client_id = ?
		    AND serial_number = ?
		  LIMIT 1`,
		tenantID, clientID, serialNumber,
	).Scan(&keyID, &caFingerprint)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrCertificateNotFound
		}
		return nil, fmt.Errorf("querying certificate for revoke: %w", err)
	}

	var existingRevokedAt time.Time
	var existingReason string

	err = tx.QueryRowContext(ctx,
		`SELECT revoked_at, reason
		   FROM revocation_events
		  WHERE tenant_id = ?
		    AND client_id = ?
		    AND serial_number = ?
		  ORDER BY revoked_at DESC, id DESC
		  LIMIT 1`,
		tenantID, clientID, serialNumber,
	).Scan(&existingRevokedAt, &existingReason)
	if err == nil {
		if err := tx.Commit(); err != nil {
			return nil, fmt.Errorf("commit already-revoked transaction: %w", err)
		}

		return &RevokedCertificate{
			SerialNumber:   serialNumber,
			KeyID:          keyID,
			CAFingerprint:  caFingerprint,
			Reason:         existingReason,
			RevokedAt:      existingRevokedAt,
			AlreadyRevoked: true,
		}, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("checking existing revocation: %w", err)
	}

	revokedAt := time.Now().UTC()

	_, err = tx.ExecContext(ctx,
		`INSERT INTO revocation_events
			(tenant_id, client_id, serial_number, key_id, ca_fingerprint, revoked_at, reason, revoked_by)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		tenantID, clientID, serialNumber, keyID, caFingerprint, revokedAt, reason, revokedBy,
	)
	if err != nil {
		return nil, fmt.Errorf("inserting revocation event: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit revoke transaction: %w", err)
	}

	return &RevokedCertificate{
		SerialNumber:   serialNumber,
		KeyID:          keyID,
		CAFingerprint:  caFingerprint,
		Reason:         reason,
		RevokedAt:      revokedAt,
		AlreadyRevoked: false,
	}, nil
}
