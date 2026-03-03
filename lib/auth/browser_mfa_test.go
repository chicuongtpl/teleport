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

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gravitational/teleport/api/client/proto"
	"github.com/gravitational/teleport/api/constants"
	mfav1 "github.com/gravitational/teleport/api/gen/proto/go/teleport/mfa/v1"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/auth"
	"github.com/gravitational/teleport/lib/auth/authtest"
	"github.com/gravitational/teleport/lib/auth/mfatypes"
	"github.com/gravitational/teleport/lib/services"
)

const redirectURL = "http://localhost:3080/callback?secret_key=test-key"

type testEnv struct {
	server       *authtest.Server
	auth         *auth.Server
	clock        *clockwork.FakeClock
	authPref     types.AuthPreference
	webauthnUser types.User
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

	// Add a WebAuthn device for the webauthn user.
	webauthnDev, err := types.NewMFADevice("webauthn-device", "webauthn-device-id", fakeClock.Now(), &types.MFADevice_Webauthn{
		Webauthn: &types.WebauthnDevice{
			CredentialId:     []byte("credential-id"),
			PublicKeyCbor:    []byte("public-key"),
			AttestationType:  "none",
			Aaguid:           []byte("aaguid"),
			SignatureCounter: 0,
			ResidentKey:      false,
		},
	})
	require.NoError(t, err)
	err = a.UpsertMFADevice(ctx, webauthnUser.GetName(), webauthnDev)
	require.NoError(t, err)

	return testEnv{
		server:       testServer,
		auth:         a,
		clock:        fakeClock,
		authPref:     authPref,
		webauthnUser: webauthnUser,
	}
}

func TestBrowserMFAChallengeCreation(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	env := newBrowserMFATestEnv(t)
	a := env.auth

	// Create a standard user without MFA devices.
	standardUser, _, err := authtest.CreateUserAndRole(a, "standard", []string{"role"}, nil)
	require.NoError(t, err)

	// Create a fake SAML user with SSO MFA enabled (shouldn't get Browser MFA challenge).
	samlUser, samlRole, err := authtest.CreateUserAndRole(a, "saml-user", []string{"role"}, nil)
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
			username: samlUser.GetName(),
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
				sd, err := a.GetSSOMFASessionData(ctx, chal.BrowserMFAChallenge.RequestId)
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
				sd, err := a.GetSSOMFASessionData(ctx, chal.BrowserMFAChallenge.RequestId)
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
