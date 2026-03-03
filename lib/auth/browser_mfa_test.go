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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gravitational/teleport/api/client/proto"
	mfav1 "github.com/gravitational/teleport/api/gen/proto/go/teleport/mfa/v1"
	"github.com/gravitational/teleport/lib/auth/authtest"
	"github.com/gravitational/teleport/lib/auth/mfatypes"
	"github.com/gravitational/teleport/lib/services"
)

func TestCreateAuthenticateChallenge_BrowserMFARequestID(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	testServer, err := authtest.NewTestServer(authtest.ServerConfig{
		Auth: authtest.AuthServerConfig{
			Dir: t.TempDir(),
		},
	})
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, testServer.Close()) })

	a := testServer.Auth()

	userCreds, err := createUserWithSecondFactors(testServer.TLS)
	require.NoError(t, err)

	tests := []struct {
		name              string
		setup             func(t *testing.T)
		browserMFAReqID   string
		requestExtensions *mfav1.ChallengeExtensions
		checkError        func(t *testing.T, err error)
		wantExtensions    *mfav1.ChallengeExtensions
	}{
		{
			name:            "NOK invalid browser MFA request ID",
			browserMFAReqID: "non-existent-id",
			requestExtensions: &mfav1.ChallengeExtensions{
				Scope: mfav1.ChallengeScope_CHALLENGE_SCOPE_LOGIN,
			},
			checkError: func(t *testing.T, err error) {
				require.True(t, trace.IsAccessDenied(err), "expected access denied error, got: %v", err)
			},
		},
		{
			name: "OK browser MFA overrides challenge extensions",
			setup: func(t *testing.T) {
				session := &services.SSOMFASessionData{
					RequestID:     "test-request-1",
					Username:      userCreds.username,
					ConnectorID:   "Browser",
					ConnectorType: "Browser",
					ChallengeExtensions: &mfatypes.ChallengeExtensions{
						Scope:                       mfav1.ChallengeScope_CHALLENGE_SCOPE_LOGIN,
						AllowReuse:                  mfav1.ChallengeAllowReuse_CHALLENGE_ALLOW_REUSE_NO,
						UserVerificationRequirement: "required",
					},
				}
				err := a.UpsertSSOMFASessionData(ctx, session)
				require.NoError(t, err)
			},
			browserMFAReqID: "test-request-1",
			requestExtensions: &mfav1.ChallengeExtensions{
				Scope:                       mfav1.ChallengeScope_CHALLENGE_SCOPE_UNSPECIFIED,
				AllowReuse:                  mfav1.ChallengeAllowReuse_CHALLENGE_ALLOW_REUSE_YES,
				UserVerificationRequirement: "discouraged",
			},
			wantExtensions: &mfav1.ChallengeExtensions{
				Scope:                       mfav1.ChallengeScope_CHALLENGE_SCOPE_LOGIN,
				AllowReuse:                  mfav1.ChallengeAllowReuse_CHALLENGE_ALLOW_REUSE_NO,
				UserVerificationRequirement: "required",
			},
		},
		{
			name: "NOK nil challenge extensions",
			setup: func(t *testing.T) {
				session := &services.SSOMFASessionData{
					RequestID:           "test-request-2",
					Username:            userCreds.username,
					ConnectorID:         "Browser",
					ConnectorType:       "Browser",
					ChallengeExtensions: nil,
				}
				err := a.UpsertSSOMFASessionData(ctx, session)
				require.NoError(t, err)
			},
			browserMFAReqID: "test-request-2",
			checkError: func(t *testing.T, err error) {
				require.True(t, trace.IsBadParameter(err), "expected bad parameter error, got: %v", err)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setup != nil {
				tt.setup(t)
			}

			var gotExtensions *mfav1.ChallengeExtensions
			a.BrowserMFAChallengeExtensionsObserver = func(ext *mfav1.ChallengeExtensions) {
				gotExtensions = ext
			}

			req := &proto.CreateAuthenticateChallengeRequest{
				Request: &proto.CreateAuthenticateChallengeRequest_UserCredentials{
					UserCredentials: &proto.UserCredentials{
						Username: userCreds.username,
						Password: userCreds.password,
					},
				},
				BrowserMFARequestID: tt.browserMFAReqID,
				ChallengeExtensions: tt.requestExtensions,
			}

			challenge, err := a.CreateAuthenticateChallenge(ctx, req)

			if tt.checkError != nil {
				require.Error(t, err)
				tt.checkError(t, err)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, challenge)
			assert.NotNil(t, challenge.WebauthnChallenge, "expected WebAuthn challenge to be present")

			if tt.wantExtensions != nil {
				require.Equal(t, tt.wantExtensions, gotExtensions)
			}
		})
	}
}
