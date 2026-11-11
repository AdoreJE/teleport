// Teleport
// Copyright (C) 2026 Gravitational, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package client

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/stretchr/testify/require"

	"github.com/gravitational/teleport/api/utils/prompt"
	wantypes "github.com/gravitational/teleport/lib/auth/webauthntypes"
)

func TestBrowserPasswordlessLogin(t *testing.T) {
	assertion := &wantypes.CredentialAssertion{
		Response: wantypes.PublicKeyCredentialRequestOptions{
			Challenge:      []byte("challenge"),
			RelyingPartyID: "teleport.example.com",
		},
	}
	response := &wantypes.CredentialAssertionResponse{
		PublicKeyCredential: wantypes.PublicKeyCredential{
			Credential: wantypes.Credential(protocol.Credential{ID: "credential", Type: "public-key"}),
			RawID:      []byte("credential"),
		},
		AssertionResponse: wantypes.AuthenticatorAssertionResponse{
			AuthenticatorResponse: wantypes.AuthenticatorResponse{
				ClientDataJSON: []byte("client-data"),
			},
			AuthenticatorData: []byte("authenticator-data"),
			Signature:         []byte("signature"),
		},
	}
	responseJSON, err := json.Marshal(response)
	require.NoError(t, err)
	stdin := prompt.NewFakeReader().AddString(base64.RawURLEncoding.EncodeToString(responseJSON))
	var stderr bytes.Buffer

	got, _, err := browserPasswordlessLogin(&stderr, stdin)(t.Context(), "", assertion, nil, nil)
	require.NoError(t, err)
	require.NotNil(t, got.GetWebauthn())
	require.Contains(t, stderr.String(), webauthnBrowserRequestPrefix)
}
