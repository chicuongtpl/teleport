// Teleport
// Copyright (C) 2026 Gravitational, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package auth

import (
	"context"
	"net/url"

	"github.com/gravitational/trace"

	mfav1 "github.com/gravitational/teleport/api/gen/proto/go/teleport/mfa/v1"
	webauthnpb "github.com/gravitational/teleport/api/types/webauthn"
	"github.com/gravitational/teleport/lib/auth/internal"
	wanlib "github.com/gravitational/teleport/lib/auth/webauthn"
	wantypes "github.com/gravitational/teleport/lib/auth/webauthntypes"
)

// ValidateBrowserMFAChallenge validates an MFA challenge response and returns the redirect URL with encrypted response.
func (a *Server) ValidateBrowserMFAChallenge(ctx context.Context, requestID string, webauthnResponse *webauthnpb.CredentialAssertionResponse) (string, error) {
	// Retrieve the MFA session
	mfaSession, err := a.GetSSOMFASession(ctx, requestID)
	if err != nil {
		return "", trace.Wrap(err)
	}

	// Get WebAuthn configuration for validation
	pref, err := a.GetAuthPreference(ctx)
	if err != nil {
		return "", trace.Wrap(err)
	}

	webConfig, err := pref.GetWebauthn()
	if err != nil {
		return "", trace.Wrap(err)
	}

	// Validate the WebAuthn response
	webLogin := &wanlib.LoginFlow{
		Webauthn: webConfig,
		Identity: a.Services,
	}

	wr := wantypes.CredentialAssertionResponseFromProto(webauthnResponse)
	// TODO(danielashare): Switch this to the Validate function once #63978 is merged
	if _, err := webLogin.Finish(ctx,
		mfaSession.Username,
		wr,
		&mfav1.ChallengeExtensions{
			Scope:                       mfaSession.ChallengeExtensions.Scope,
			AllowReuse:                  mfaSession.ChallengeExtensions.AllowReuse,
			UserVerificationRequirement: mfaSession.ChallengeExtensions.UserVerificationRequirement,
		},
	); err != nil {
		return "", trace.Wrap(err, "failed to validate browser MFA response")
	}

	// Valid WebAuthn response, encrypt and return it
	u, err := url.Parse(mfaSession.ClientRedirectURL)
	if err != nil {
		return "", trace.Wrap(err)
	}

	clientRedirectURL, err := internal.EncryptBrowserMFAResponse(u, wr)
	if err != nil {
		return "", trace.Wrap(err)
	}

	return clientRedirectURL, nil
}
