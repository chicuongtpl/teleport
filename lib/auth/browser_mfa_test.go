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

package auth_test

import (
	"context"
	"testing"

	"github.com/gravitational/trace"
	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gravitational/teleport/api/client/proto"
	"github.com/gravitational/teleport/api/constants"
	mfav1 "github.com/gravitational/teleport/api/gen/proto/go/teleport/mfa/v1"
	"github.com/gravitational/teleport/api/types"
	webauthnpb "github.com/gravitational/teleport/api/types/webauthn"
	"github.com/gravitational/teleport/lib/auth"
	"github.com/gravitational/teleport/lib/auth/authtest"
	"github.com/gravitational/teleport/lib/auth/mfatypes"
	wanlib "github.com/gravitational/teleport/lib/auth/webauthn"
	wantypes "github.com/gravitational/teleport/lib/auth/webauthntypes"
	"github.com/gravitational/teleport/lib/authz"
	"github.com/gravitational/teleport/lib/services"
)

const redirectURL = "http://localhost:3080/callback?secret_key=test-key"

type testEnv struct {
	server       *authtest.Server
	auth         *auth.Server
	clock        *clockwork.FakeClock
	authPref     types.AuthPreference
	webauthnUser types.User
	webauthnDev  *authtest.Device
	samlMFAUser  types.User
}

func newBrowserMFATestEnv(t *testing.T) testEnv {
	t.Helper()
	ctx := t.Context()

	fakeClock := clockwork.NewFakeClock()
	testServer, err := authtest.NewTestServer(authtest.ServerConfig{
		Auth: authtest.AuthServerConfig{
			Dir:   t.TempDir(),
			Clock: fakeClock,
		},
	})
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, testServer.Close()) })

	a := testServer.Auth()

	// Register a proxy server so getProxyPublicAddr returns a valid address.
	proxy, err := types.NewServer("test-proxy", types.KindProxy, types.ServerSpecV2{
		PublicAddrs: []string{"proxy.example.com:443"},
	})
	require.NoError(t, err)
	err = a.UpsertProxy(ctx, proxy)
	require.NoError(t, err)

	// Enable WebAuthn support.
	authPref, err := types.NewAuthPreference(types.AuthPreferenceSpecV2{
		Type:         constants.Local,
		SecondFactor: constants.SecondFactorWebauthn,
		Webauthn: &types.Webauthn{
			RPID: "localhost",
		},
		AllowBrowserAuthentication: types.NewBoolOption(true),
	})
	require.NoError(t, err)
	_, err = a.UpsertAuthPreference(ctx, authPref)
	require.NoError(t, err)

	// Create a user with a WebAuthn device.
	webauthnUser, _, err := authtest.CreateUserAndRole(a, "webauthn-user", []string{"role"}, nil)
	require.NoError(t, err)

	webauthnClient, err := testServer.NewClient(authtest.TestUser(webauthnUser.GetName()))
	require.NoError(t, err)

	// Register the webauthn device
	webauthnDev, err := authtest.RegisterTestDevice(ctx, webauthnClient, "webauthn-device", proto.DeviceType_DEVICE_TYPE_WEBAUTHN, nil)
	require.NoError(t, err)

	// Create a fake SAML user with SSO MFA enabled.
	samlMFAUser, samlRole, err := authtest.CreateUserAndRole(a, "saml-user", []string{"role"}, nil)
	require.NoError(t, err)

	samlConnector, err := types.NewSAMLConnector("saml", types.SAMLConnectorSpecV2{
		AssertionConsumerService: "http://localhost:65535/acs",
		Issuer:                   "test",
		SSO:                      "https://localhost:65535/sso",
		AttributesToRoles: []types.AttributeMapping{
			{Name: "groups", Value: "admin", Roles: []string{samlRole.GetName()}},
		},
		MFASettings: &types.SAMLConnectorMFASettings{
			Enabled: true,
			Issuer:  "test",
			Sso:     "https://localhost:65535/sso",
		},
	})
	require.NoError(t, err)
	_, err = a.UpsertSAMLConnector(ctx, samlConnector)
	require.NoError(t, err)

	samlMFAUser.SetCreatedBy(types.CreatedBy{
		Time: a.GetClock().Now(),
		Connector: &types.ConnectorRef{
			ID:   samlConnector.GetName(),
			Type: samlConnector.GetKind(),
		},
	})
	_, err = a.UpsertUser(ctx, samlMFAUser)
	require.NoError(t, err)

	return testEnv{
		server:       testServer,
		auth:         a,
		clock:        fakeClock,
		authPref:     authPref,
		webauthnUser: webauthnUser,
		webauthnDev:  webauthnDev,
		samlMFAUser:  samlMFAUser,
	}
}

func newBrowserMFASessionData(sessionID, username string, ext *mfav1.ChallengeExtensions) *services.MFASessionData {
	challengeExt := &mfatypes.ChallengeExtensions{}
	if ext != nil {
		challengeExt.Scope = ext.Scope
		challengeExt.AllowReuse = ext.AllowReuse
		challengeExt.UserVerificationRequirement = ext.UserVerificationRequirement
	}

	return &services.MFASessionData{
		RequestID:           sessionID,
		Username:            username,
		ConnectorID:         constants.BrowserMFA,
		ConnectorType:       constants.BrowserMFA,
		ChallengeExtensions: challengeExt,
	}
}

func beginAndSolveBrowserMFAWebauthn(t *testing.T, env testEnv, ext *mfav1.ChallengeExtensions) *webauthnpb.CredentialAssertionResponse {
	t.Helper()

	waConfig, err := env.authPref.GetWebauthn()
	require.NoError(t, err)

	loginFlow := &wanlib.LoginFlow{
		Webauthn: waConfig,
		Identity: env.auth.Services,
	}

	assertion, err := loginFlow.Begin(t.Context(), wanlib.BeginParams{
		User:                env.webauthnUser.GetName(),
		ChallengeExtensions: ext,
	})
	require.NoError(t, err)

	assertionResp, err := env.webauthnDev.Key.SignAssertion(env.webauthnDev.Origin(), assertion)
	require.NoError(t, err)

	return wantypes.CredentialAssertionResponseToProto(assertionResp)
}

func TestBrowserMFAChallengeCreation(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	env := newBrowserMFATestEnv(t)
	a := env.auth

	// Create a standard user without MFA devices.
	standardUser, _, err := authtest.CreateUserAndRole(a, "standard", []string{"role"}, nil)
	require.NoError(t, err)

	loginExt := &mfav1.ChallengeExtensions{
		Scope: mfav1.ChallengeScope_CHALLENGE_SCOPE_LOGIN,
	}

	for _, tt := range []struct {
		name             string
		username         string
		setup            func(t *testing.T)
		challengeRequest *proto.CreateAuthenticateChallengeRequest
		checkError       func(t *testing.T, err error)
		assertChallenge  func(t *testing.T, chal *proto.MFAAuthenticateChallenge)
	}{
		{
			name:     "NOK user without WebAuthn devices",
			username: standardUser.GetName(),
			challengeRequest: &proto.CreateAuthenticateChallengeRequest{
				ChallengeExtensions:      loginExt,
				BrowserMFATSHRedirectURL: redirectURL,
			},
			assertChallenge: func(t *testing.T, chal *proto.MFAAuthenticateChallenge) {
				assert.Nil(t, chal.BrowserMFAChallenge, "should not return Browser MFA challenge for user without WebAuthn devices")
			},
		},
		{
			name:     "NOK BrowserMFATSHRedirectURL not provided",
			username: env.webauthnUser.GetName(),
			challengeRequest: &proto.CreateAuthenticateChallengeRequest{
				ChallengeExtensions:      loginExt,
				BrowserMFATSHRedirectURL: "",
			},
			assertChallenge: func(t *testing.T, chal *proto.MFAAuthenticateChallenge) {
				assert.Nil(t, chal.BrowserMFAChallenge, "should not return Browser MFA challenge when BrowserMFATSHRedirectURL is empty")
			},
		},
		{
			name:     "NOK Browser authentication disabled by auth preference",
			username: env.webauthnUser.GetName(),
			challengeRequest: &proto.CreateAuthenticateChallengeRequest{
				ChallengeExtensions:      loginExt,
				BrowserMFATSHRedirectURL: redirectURL,
			},
			setup: func(t *testing.T) {
				// Disable Browser authentication.
				env.authPref.SetAllowBrowserAuthentication(false)
				_, err = a.UpsertAuthPreference(ctx, env.authPref)
				require.NoError(t, err)
				t.Cleanup(func() {
					env.authPref.SetAllowBrowserAuthentication(true)
					_, err = a.UpsertAuthPreference(ctx, env.authPref)
					assert.NoError(t, err)
				})
			},
			assertChallenge: func(t *testing.T, chal *proto.MFAAuthenticateChallenge) {
				assert.Nil(t, chal.BrowserMFAChallenge, "should not return Browser MFA challenge when AllowBrowserAuthentication is false")
			},
		},
		{
			name:     "NOK SSO MFA user should not get Browser MFA",
			username: env.samlMFAUser.GetName(),
			challengeRequest: &proto.CreateAuthenticateChallengeRequest{
				ChallengeExtensions:      loginExt,
				BrowserMFATSHRedirectURL: redirectURL,
			},
			assertChallenge: func(t *testing.T, chal *proto.MFAAuthenticateChallenge) {
				assert.Nil(t, chal.BrowserMFAChallenge, "SSO MFA users should not get Browser MFA challenge")
			},
		},
		{
			name:     "OK WebAuthn user gets Browser MFA challenge",
			username: env.webauthnUser.GetName(),
			challengeRequest: &proto.CreateAuthenticateChallengeRequest{
				ChallengeExtensions:      loginExt,
				BrowserMFATSHRedirectURL: redirectURL,
			},
			assertChallenge: func(t *testing.T, chal *proto.MFAAuthenticateChallenge) {
				require.NotNil(t, chal.BrowserMFAChallenge, "expected Browser MFA challenge to be returned")
				assert.NotEmpty(t, chal.BrowserMFAChallenge.RequestId, "request ID should be generated")

				// Find SSO MFA session data tied to the challenge.
				// Browser MFA reuses the SSO MFA session data storage.
				sd, err := a.GetMFASessionData(ctx, chal.BrowserMFAChallenge.RequestId)
				require.NoError(t, err)
				assert.Equal(t, &services.MFASessionData{
					RequestID:      chal.BrowserMFAChallenge.RequestId,
					Username:       env.webauthnUser.GetName(),
					ConnectorID:    constants.BrowserMFA,
					ConnectorType:  constants.BrowserMFA,
					TSHRedirectURL: redirectURL,
					ChallengeExtensions: &mfatypes.ChallengeExtensions{
						Scope: mfav1.ChallengeScope_CHALLENGE_SCOPE_LOGIN,
					},
				}, sd)
			},
		},
		{
			name:     "OK allow reuse",
			username: env.webauthnUser.GetName(),
			challengeRequest: &proto.CreateAuthenticateChallengeRequest{
				ChallengeExtensions: &mfav1.ChallengeExtensions{
					Scope:      mfav1.ChallengeScope_CHALLENGE_SCOPE_USER_SESSION,
					AllowReuse: mfav1.ChallengeAllowReuse_CHALLENGE_ALLOW_REUSE_YES,
				},
				BrowserMFATSHRedirectURL: redirectURL,
			},
			assertChallenge: func(t *testing.T, chal *proto.MFAAuthenticateChallenge) {
				require.NotNil(t, chal.BrowserMFAChallenge, "expected Browser MFA challenge to be returned")

				// We should find SSO MFA session data tied to the challenge by request ID.
				sd, err := a.GetMFASessionData(ctx, chal.BrowserMFAChallenge.RequestId)
				require.NoError(t, err)
				assert.Equal(t, mfav1.ChallengeAllowReuse_CHALLENGE_ALLOW_REUSE_YES, sd.ChallengeExtensions.AllowReuse)
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			userClient, err := env.server.NewClient(authtest.TestUser(tt.username))
			require.NoError(t, err)

			if tt.setup != nil {
				tt.setup(t)
			}

			chal, err := userClient.CreateAuthenticateChallenge(ctx, tt.challengeRequest)

			if tt.checkError != nil {
				require.Error(t, err)
				tt.checkError(t, err)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, chal)
			if tt.assertChallenge != nil {
				tt.assertChallenge(t, chal)
			}
		})
	}
}

func TestVerifyBrowserMFASession(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	const notFoundErrMsg = "browser mfa session data not found"
	loginExt := &mfav1.ChallengeExtensions{
		Scope: mfav1.ChallengeScope_CHALLENGE_SCOPE_LOGIN,
	}

	t.Run("bad parameter when requiredExtensions or webauthnResponse is nil", func(t *testing.T) {
		env := newBrowserMFATestEnv(t)
		sessionID := "session-id"
		err := env.auth.UpsertMFASessionData(ctx, newBrowserMFASessionData(sessionID, env.webauthnUser.GetName(), loginExt))
		require.NoError(t, err)

		validResp := beginAndSolveBrowserMFAWebauthn(t, env, loginExt)

		for _, tt := range []struct {
			name               string
			requiredExtensions *mfav1.ChallengeExtensions
			webauthnResponse   *webauthnpb.CredentialAssertionResponse
			wantErr            string
		}{
			{
				name:             "missing required extensions",
				webauthnResponse: validResp,
				wantErr:          "requested challenge extensions must be supplied",
			},
			{
				name:               "missing webauthn response",
				requiredExtensions: loginExt,
				wantErr:            "webauthn response must be supplied",
			},
		} {
			t.Run(tt.name, func(t *testing.T) {
				authData, err := env.auth.VerifyBrowserMFASession(ctx, env.webauthnUser.GetName(), sessionID, tt.webauthnResponse, tt.requiredExtensions)
				require.Nil(t, authData)
				require.True(t, trace.IsBadParameter(err), "expected bad parameter error but got %v", err)
				require.ErrorContains(t, err, tt.wantErr)
			})
		}
	})

	t.Run("same not found error for missing session and username mismatch", func(t *testing.T) {
		env := newBrowserMFATestEnv(t)

		for _, tt := range []struct {
			name  string
			setup func(t *testing.T)
		}{
			{
				name: "session not found", // MFASessionData not created
			},
			{
				name: "username mismatch",
				setup: func(t *testing.T) {
					err := env.auth.UpsertMFASessionData(ctx, newBrowserMFASessionData("session-id", "someone-else", loginExt))
					require.NoError(t, err)
				},
			},
		} {
			t.Run(tt.name, func(t *testing.T) {
				if tt.setup != nil {
					tt.setup(t)
				}

				mad, err := env.auth.VerifyBrowserMFASession(ctx, env.webauthnUser.GetName(), "session-id", &webauthnpb.CredentialAssertionResponse{}, loginExt)
				require.Nil(t, mad)
				require.True(t, trace.IsNotFound(err), "expected not found error but got %v", err)
				require.EqualError(t, err, notFoundErrMsg)
			})
		}
	})

	t.Run("access denied when browser mfa device is unavailable", func(t *testing.T) {
		for _, tt := range []struct {
			name          string
			sessionID     string
			setup         func(t *testing.T, env testEnv) string
			wantErrSubstr string
		}{
			{
				name:      "no webauthn devices",
				sessionID: "no-device-session",
				setup: func(t *testing.T, env testEnv) string {
					user, _, err := authtest.CreateUserAndRole(env.auth, "standard-user", []string{"role"}, nil)
					require.NoError(t, err)
					err = env.auth.UpsertMFASessionData(ctx, newBrowserMFASessionData("no-device-session", user.GetName(), loginExt))
					require.NoError(t, err)
					return user.GetName()
				},
				wantErrSubstr: "no webauthn devices are registered",
			},
			{
				name:      "sso mfa available",
				sessionID: "sso-device-session",
				setup: func(t *testing.T, env testEnv) string {
					err := env.auth.UpsertMFASessionData(ctx, newBrowserMFASessionData("sso-device-session", env.samlMFAUser.GetName(), loginExt))
					require.NoError(t, err)
					return env.samlMFAUser.GetName()
				},
				wantErrSubstr: "SSO MFA is available (preferred over Browser MFA)",
			},
		} {
			t.Run(tt.name, func(t *testing.T) {
				env := newBrowserMFATestEnv(t)
				username := tt.setup(t, env)

				mad, err := env.auth.VerifyBrowserMFASession(ctx, username, tt.sessionID, &webauthnpb.CredentialAssertionResponse{}, loginExt)
				require.Nil(t, mad)
				require.True(t, trace.IsAccessDenied(err), "expected access denied error but got %v", err)
				require.ErrorContains(t, err, "user has no browser mfa device available")
				require.ErrorContains(t, err, tt.wantErrSubstr)
			})
		}
	})

	t.Run("access denied when scope or allow reuse does not match", func(t *testing.T) {
		for _, tt := range []struct {
			name               string
			sessionID          string
			sessionExtensions  *mfav1.ChallengeExtensions
			requiredExtensions *mfav1.ChallengeExtensions
			wantErr            string
		}{
			{
				name:      "scope mismatch",
				sessionID: "scope-mismatch",
				sessionExtensions: &mfav1.ChallengeExtensions{
					Scope: mfav1.ChallengeScope_CHALLENGE_SCOPE_LOGIN,
				},
				requiredExtensions: &mfav1.ChallengeExtensions{
					Scope: mfav1.ChallengeScope_CHALLENGE_SCOPE_ADMIN_ACTION,
				},
				wantErr: "required scope",
			},
			{
				name:      "reuse mismatch",
				sessionID: "reuse-mismatch",
				sessionExtensions: &mfav1.ChallengeExtensions{
					Scope:      mfav1.ChallengeScope_CHALLENGE_SCOPE_USER_SESSION,
					AllowReuse: mfav1.ChallengeAllowReuse_CHALLENGE_ALLOW_REUSE_YES,
				},
				requiredExtensions: &mfav1.ChallengeExtensions{
					Scope:      mfav1.ChallengeScope_CHALLENGE_SCOPE_USER_SESSION,
					AllowReuse: mfav1.ChallengeAllowReuse_CHALLENGE_ALLOW_REUSE_NO,
				},
				wantErr: "reuse is not permitted",
			},
		} {
			t.Run(tt.name, func(t *testing.T) {
				env := newBrowserMFATestEnv(t)
				err := env.auth.UpsertMFASessionData(ctx, newBrowserMFASessionData(tt.sessionID, env.webauthnUser.GetName(), tt.sessionExtensions))
				require.NoError(t, err)

				authData, err := env.auth.VerifyBrowserMFASession(ctx, env.webauthnUser.GetName(), tt.sessionID, &webauthnpb.CredentialAssertionResponse{}, tt.requiredExtensions)
				require.Nil(t, authData)
				require.True(t, trace.IsAccessDenied(err), "expected access denied error but got %v", err)
				require.ErrorContains(t, err, tt.wantErr)
			})
		}
	})

	t.Run("deletes session when reuse is not allowed", func(t *testing.T) {
		env := newBrowserMFATestEnv(t)
		sessionID := "no-reuse-success"
		sessionExt := &mfav1.ChallengeExtensions{
			Scope:      mfav1.ChallengeScope_CHALLENGE_SCOPE_LOGIN,
			AllowReuse: mfav1.ChallengeAllowReuse_CHALLENGE_ALLOW_REUSE_NO,
		}
		err := env.auth.UpsertMFASessionData(ctx, newBrowserMFASessionData(sessionID, env.webauthnUser.GetName(), sessionExt))
		require.NoError(t, err)

		webResp := beginAndSolveBrowserMFAWebauthn(t, env, sessionExt)

		authData, err := env.auth.VerifyBrowserMFASession(ctx, env.webauthnUser.GetName(), sessionID, webResp, sessionExt)
		require.NoError(t, err)
		require.NotNil(t, authData)

		_, err = env.auth.GetMFASessionData(ctx, sessionID)
		require.True(t, trace.IsNotFound(err), "expected session to be deleted but got %v", err)
	})

	t.Run("returns login data on success and session reuse maintained", func(t *testing.T) {
		env := newBrowserMFATestEnv(t)
		sessionID := "reuse-success"
		sessionExt := &mfav1.ChallengeExtensions{
			Scope:      mfav1.ChallengeScope_CHALLENGE_SCOPE_USER_SESSION,
			AllowReuse: mfav1.ChallengeAllowReuse_CHALLENGE_ALLOW_REUSE_YES,
		}
		sd := newBrowserMFASessionData(sessionID, env.webauthnUser.GetName(), sessionExt)
		err := env.auth.UpsertMFASessionData(ctx, sd)
		require.NoError(t, err)

		webResp := beginAndSolveBrowserMFAWebauthn(t, env, sessionExt)

		authData, err := env.auth.VerifyBrowserMFASession(ctx, env.webauthnUser.GetName(), sessionID, webResp, sessionExt)
		require.NoError(t, err)
		require.Equal(t, &authz.MFAAuthData{
			Device:        authData.Device,
			User:          env.webauthnUser.GetName(),
			AllowReuse:    mfav1.ChallengeAllowReuse_CHALLENGE_ALLOW_REUSE_YES,
			MFAViaBrowser: true,
		}, authData)
		require.Equal(t, env.webauthnDev.MFA.GetName(), authData.Device.GetName())

		storedSession, err := env.auth.GetMFASessionData(ctx, sessionID)
		require.NoError(t, err)
		require.Equal(t, mfav1.ChallengeAllowReuse_CHALLENGE_ALLOW_REUSE_YES, storedSession.ChallengeExtensions.AllowReuse)
	})
}
