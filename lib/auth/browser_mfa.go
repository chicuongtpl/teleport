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
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/gravitational/trace"

	"github.com/gravitational/teleport/api/client/proto"
	"github.com/gravitational/teleport/api/constants"
	mfav1 "github.com/gravitational/teleport/api/gen/proto/go/teleport/mfa/v1"
	webauthnpb "github.com/gravitational/teleport/api/types/webauthn"
	"github.com/gravitational/teleport/lib/auth/mfatypes"
	wanlib "github.com/gravitational/teleport/lib/auth/webauthn"
	wantypes "github.com/gravitational/teleport/lib/auth/webauthntypes"
	"github.com/gravitational/teleport/lib/authz"
	"github.com/gravitational/teleport/lib/client/sso"
)

// BeginBrowserMFAChallenge creates a new Browser MFA auth request and session
// data for the given which is stored in the backend.
func (a *Server) BeginBrowserMFAChallenge(ctx context.Context, params mfatypes.BeginBrowserMFAChallengeParams) (*proto.BrowserMFAChallenge, error) {
	if err := sso.ValidateClientRedirect(params.BrowserMFATSHRedirectURL, sso.CeremonyTypeMFA, nil); err != nil {
		return nil, trace.Wrap(err, InvalidClientRedirectErrorMessage)
	}

	requestID := uuid.NewString()
	browserChal := &proto.BrowserMFAChallenge{
		RequestId: requestID,
	}

	if err := a.upsertMFASession(ctx, upsertMFASessionParams{
		user:           params.User,
		sessionID:      requestID,
		connectorID:    constants.BrowserMFA,
		connectorType:  constants.BrowserMFA,
		tshRedirectURL: params.BrowserMFATSHRedirectURL,
		ext:            params.Ext,
		sip:            params.SIP,
		sourceCluster:  params.SourceCluster,
		targetCluster:  params.TargetCluster,
	}); err != nil {
		return nil, trace.Wrap(err)
	}

	return browserChal, nil
}

// VerifyBrowserMFASession verifies that the given Browser MFA webauthn response matches an existing MFA session
// for the user and session ID. It also checks the required extensions, and finishes by deleting
// the MFA session if reuse is not allowed.
func (a *Server) VerifyBrowserMFASession(ctx context.Context, username, sessionID string, webauthnResponse *webauthnpb.CredentialAssertionResponse, requiredExtensions *mfav1.ChallengeExtensions) (*authz.MFAAuthData, error) {
	if requiredExtensions == nil {
		return nil, trace.BadParameter("requested challenge extensions must be supplied.")
	}

	if webauthnResponse == nil {
		return nil, trace.BadParameter("webauthn response must be supplied")
	}

	const notFoundErrMsg = "browser mfa session data not found"
	mfaSess, err := a.GetMFASessionData(ctx, sessionID)
	if trace.IsNotFound(err) {
		return nil, trace.NotFound("%s", notFoundErrMsg)
	} else if err != nil {
		return nil, trace.Wrap(err)
	}

	// Verify the user's name matches.
	if mfaSess.Username != username {
		return nil, trace.NotFound("%s", notFoundErrMsg)
	}

	// Verify this is a Browser MFA session and not an SSO MFA session.
	if mfaSess.TSHRedirectURL == "" && mfaSess.ConnectorID != constants.BrowserMFA {
		a.logger.WarnContext(ctx,
			"The Browser MFA flow was used to access a SSO MFA session.",
			"request_id", mfaSess.RequestID,
			"connector_id", mfaSess.ConnectorID,
			"username", username,
		)
		return nil, trace.NotFound("%s", notFoundErrMsg)
	}

	// Check if the MFA session matches the user's Browser MFA settings.
	devs, err := a.Services.GetMFADevices(ctx, username, false /* withSecrets */)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// Check the user has a Browser MFA device
	groupedDevs := groupByDeviceType(devs)
	if groupedDevs.Browser == nil {
		a.logger.DebugContext(ctx,
			"Browser MFA failed. It isn't available when a user has no WebAuthn devices or has SSO MFA",
			"webauthn_devices", len(groupedDevs.Webauthn),
			"sso_mfa_available", groupedDevs.SSO != nil,
			"user", username,
		)

		var cause []string
		if len(groupedDevs.Webauthn) == 0 {
			cause = append(cause, "no webauthn devices are registered")
		}
		if groupedDevs.SSO != nil {
			cause = append(cause, "SSO MFA is available (preferred over Browser MFA)")
		}
		accessDeniedMsg := "user has no browser mfa device available"
		if len(cause) > 0 {
			accessDeniedMsg += fmt.Sprintf(" because %s", strings.Join(cause, " and "))
		}
		return nil, trace.AccessDenied("%s", accessDeniedMsg)
	}

	// Check if the given scope is satisfied by the challenge scope.
	if requiredExtensions.Scope != mfaSess.ChallengeExtensions.Scope {
		return nil, trace.AccessDenied("required scope %q is not satisfied by the given browser mfa session with scope %q", requiredExtensions.Scope, mfaSess.ChallengeExtensions.Scope)
	}

	// If this session is reusable, but this context forbids reusable sessions, return an error.
	if requiredExtensions.AllowReuse == mfav1.ChallengeAllowReuse_CHALLENGE_ALLOW_REUSE_NO && mfaSess.ChallengeExtensions.AllowReuse == mfav1.ChallengeAllowReuse_CHALLENGE_ALLOW_REUSE_YES {
		return nil, trace.AccessDenied("the given browser mfa session allows reuse, but reuse is not permitted in this context")
	}

	// Convert from protobuf type to wantypes
	wanResp := wantypes.CredentialAssertionResponseFromProto(webauthnResponse)

	cap, err := a.GetAuthPreference(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	waConfig, err := cap.GetWebauthn()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	loginFlow := &wanlib.LoginFlow{
		Webauthn: waConfig,
		Identity: a.Services,
	}

	// Verify webauthn response
	loginData, err := loginFlow.Finish(ctx, username, wanResp, &mfav1.ChallengeExtensions{
		Scope:      mfaSess.ChallengeExtensions.Scope,
		AllowReuse: mfaSess.ChallengeExtensions.AllowReuse,
	})
	if err != nil {
		return nil, trace.AccessDenied("verify WebAuthn response: %v", err)
	}

	if mfaSess.ChallengeExtensions.AllowReuse != mfav1.ChallengeAllowReuse_CHALLENGE_ALLOW_REUSE_YES {
		if err := a.DeleteMFASessionData(ctx, sessionID); err != nil {
			return nil, trace.Wrap(err)
		}
	}

	return &authz.MFAAuthData{
		Device:        loginData.Device,
		User:          username,
		AllowReuse:    mfaSess.ChallengeExtensions.AllowReuse,
		Payload:       mfaSess.Payload,
		SourceCluster: mfaSess.SourceCluster,
		TargetCluster: mfaSess.TargetCluster,
		MFAViaBrowser: true,
	}, nil
}
