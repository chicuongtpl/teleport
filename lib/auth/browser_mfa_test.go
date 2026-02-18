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

	as, err := authtest.NewAuthServer(authtest.AuthServerConfig{
		Dir: t.TempDir(),
	})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, as.Close()) })

	srv, err := as.NewTestTLSServer()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, srv.Close()) })

	a := srv.Auth()

	// Create a test user with password.
	username := "test-user"
	password := "test-password"
	_, _, err = authtest.CreateUserAndRole(a, username, []string{"role"}, nil)
	require.NoError(t, err)
	err = a.UpsertPassword(username, []byte(password))
	require.NoError(t, err)

	tests := []struct {
		name              string
		setup             func(t *testing.T)
		browserMFAReqID   string
		requestExtensions *mfav1.ChallengeExtensions
		wantError         bool
		checkExtensions   func(t *testing.T, extensions *mfav1.ChallengeExtensions)
	}{
		{
			name:            "NOK invalid browser MFA request ID",
			browserMFAReqID: "non-existent-id",
			requestExtensions: &mfav1.ChallengeExtensions{
				Scope: mfav1.ChallengeScope_CHALLENGE_SCOPE_LOGIN,
			},
			wantError: true,
		},
		{
			name: "OK browser MFA request with scope set to LOGIN",
			setup: func(t *testing.T) {
				session := &services.SSOMFASessionData{
					RequestID:     "test-request-1",
					Username:      username,
					ConnectorID:   "Browser",
					ConnectorType: "Browser",
					ChallengeExtensions: &mfatypes.ChallengeExtensions{
						Scope: mfav1.ChallengeScope_CHALLENGE_SCOPE_LOGIN,
					},
				}
				err := a.UpsertSSOMFASessionData(ctx, session)
				require.NoError(t, err)
			},
			browserMFAReqID: "test-request-1",
			requestExtensions: &mfav1.ChallengeExtensions{
				Scope: mfav1.ChallengeScope_CHALLENGE_SCOPE_UNSPECIFIED,
			},
			wantError: false,
			checkExtensions: func(t *testing.T, extensions *mfav1.ChallengeExtensions) {
				require.Equal(t, mfav1.ChallengeScope_CHALLENGE_SCOPE_LOGIN, extensions.Scope)
			},
		},
		{
			name: "OK browser MFA request with allow reuse override",
			setup: func(t *testing.T) {
				session := &services.SSOMFASessionData{
					RequestID:     "test-request-2",
					Username:      username,
					ConnectorID:   "Browser",
					ConnectorType: "Browser",
					ChallengeExtensions: &mfatypes.ChallengeExtensions{
						AllowReuse: mfav1.ChallengeAllowReuse_CHALLENGE_ALLOW_REUSE_YES,
					},
				}
				err := a.UpsertSSOMFASessionData(ctx, session)
				require.NoError(t, err)
			},
			browserMFAReqID: "test-request-2",
			requestExtensions: &mfav1.ChallengeExtensions{
				AllowReuse: mfav1.ChallengeAllowReuse_CHALLENGE_ALLOW_REUSE_NO,
			},
			wantError: false,
			checkExtensions: func(t *testing.T, extensions *mfav1.ChallengeExtensions) {
				require.Equal(t, mfav1.ChallengeAllowReuse_CHALLENGE_ALLOW_REUSE_YES, extensions.AllowReuse)
			},
		},
		{
			name: "OK browser MFA request with user verification requirement override",
			setup: func(t *testing.T) {
				session := &services.SSOMFASessionData{
					RequestID:     "test-request-3",
					Username:      username,
					ConnectorID:   "Browser",
					ConnectorType: "Browser",
					ChallengeExtensions: &mfatypes.ChallengeExtensions{
						UserVerificationRequirement: "required",
					},
				}
				err := a.UpsertSSOMFASessionData(ctx, session)
				require.NoError(t, err)
			},
			browserMFAReqID: "test-request-3",
			requestExtensions: &mfav1.ChallengeExtensions{
				UserVerificationRequirement: "preferred",
			},
			wantError: false,
			checkExtensions: func(t *testing.T, extensions *mfav1.ChallengeExtensions) {
				require.Equal(t, "required", extensions.UserVerificationRequirement)
			},
		},
		{
			name: "OK browser MFA request with unspecified scope preserves request scope",
			setup: func(t *testing.T) {
				session := &services.SSOMFASessionData{
					RequestID:     "test-request-4",
					Username:      username,
					ConnectorID:   "Browser",
					ConnectorType: "Browser",
					ChallengeExtensions: &mfatypes.ChallengeExtensions{
						Scope: mfav1.ChallengeScope_CHALLENGE_SCOPE_UNSPECIFIED,
					},
				}
				err := a.UpsertSSOMFASessionData(ctx, session)
				require.NoError(t, err)
			},
			browserMFAReqID: "test-request-4",
			requestExtensions: &mfav1.ChallengeExtensions{
				Scope: mfav1.ChallengeScope_CHALLENGE_SCOPE_LOGIN,
			},
			wantError: false,
			checkExtensions: func(t *testing.T, extensions *mfav1.ChallengeExtensions) {
				require.Equal(t, mfav1.ChallengeScope_CHALLENGE_SCOPE_LOGIN, extensions.Scope)
			},
		},
		{
			name: "OK browser MFA request with unspecified allow reuse preserves request value",
			setup: func(t *testing.T) {
				session := &services.SSOMFASessionData{
					RequestID:     "test-request-5",
					Username:      username,
					ConnectorID:   "Browser",
					ConnectorType: "Browser",
					ChallengeExtensions: &mfatypes.ChallengeExtensions{
						AllowReuse: mfav1.ChallengeAllowReuse_CHALLENGE_ALLOW_REUSE_UNSPECIFIED,
					},
				}
				err := a.UpsertSSOMFASessionData(ctx, session)
				require.NoError(t, err)
			},
			browserMFAReqID: "test-request-5",
			requestExtensions: &mfav1.ChallengeExtensions{
				AllowReuse: mfav1.ChallengeAllowReuse_CHALLENGE_ALLOW_REUSE_YES,
			},
			wantError: false,
			checkExtensions: func(t *testing.T, extensions *mfav1.ChallengeExtensions) {
				require.Equal(t, mfav1.ChallengeAllowReuse_CHALLENGE_ALLOW_REUSE_YES, extensions.AllowReuse)
			},
		},
		{
			name: "OK browser MFA request with empty user verification requirement preserves request value",
			setup: func(t *testing.T) {
				session := &services.SSOMFASessionData{
					RequestID:     "test-request-6",
					Username:      username,
					ConnectorID:   "Browser",
					ConnectorType: "Browser",
					ChallengeExtensions: &mfatypes.ChallengeExtensions{
						UserVerificationRequirement: "",
					},
				}
				err := a.UpsertSSOMFASessionData(ctx, session)
				require.NoError(t, err)
			},
			browserMFAReqID: "test-request-6",
			requestExtensions: &mfav1.ChallengeExtensions{
				UserVerificationRequirement: "discouraged",
			},
			wantError: false,
			checkExtensions: func(t *testing.T, extensions *mfav1.ChallengeExtensions) {
				require.Equal(t, "discouraged", extensions.UserVerificationRequirement)
			},
		},
		{
			name: "OK browser MFA request with nil challenge extensions preserves request",
			setup: func(t *testing.T) {
				session := &services.SSOMFASessionData{
					RequestID:           "test-request-7",
					Username:            username,
					ConnectorID:         "test-connector",
					ConnectorType:       "test",
					ChallengeExtensions: nil,
				}
				err := a.UpsertSSOMFASessionData(ctx, session)
				require.NoError(t, err)
			},
			browserMFAReqID: "test-request-7",
			requestExtensions: &mfav1.ChallengeExtensions{
				Scope:                       mfav1.ChallengeScope_CHALLENGE_SCOPE_LOGIN,
				AllowReuse:                  mfav1.ChallengeAllowReuse_CHALLENGE_ALLOW_REUSE_NO,
				UserVerificationRequirement: "preferred",
			},
			wantError: false,
			checkExtensions: func(t *testing.T, extensions *mfav1.ChallengeExtensions) {
				require.Equal(t, mfav1.ChallengeScope_CHALLENGE_SCOPE_LOGIN, extensions.Scope)
				require.Equal(t, mfav1.ChallengeAllowReuse_CHALLENGE_ALLOW_REUSE_NO, extensions.AllowReuse)
				require.Equal(t, "preferred", extensions.UserVerificationRequirement)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setup != nil {
				tt.setup(t)
			}

			req := &proto.CreateAuthenticateChallengeRequest{
				Request: &proto.CreateAuthenticateChallengeRequest_UserCredentials{
					UserCredentials: &proto.UserCredentials{
						Username: username,
						Password: []byte(password),
					},
				},
				BrowserMFARequestID: tt.browserMFAReqID,
				ChallengeExtensions: tt.requestExtensions,
			}

			challenge, err := a.CreateAuthenticateChallenge(ctx, req)

			if tt.wantError {
				require.Error(t, err)
				require.True(t, trace.IsAccessDenied(err), "expected access denied error, got: %v", err)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, challenge)

			if tt.checkExtensions != nil {
				tt.checkExtensions(t, req.ChallengeExtensions)
			}
		})
	}
}
