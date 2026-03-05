/*
 * Teleport
 * Copyright (C) 2026  Gravitational, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package reexec

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	decisionpb "github.com/gravitational/teleport/api/gen/proto/go/teleport/decision/v1alpha1"
)

func TestReadChildError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		stderr  string
		context *ErrorContext
		want    string
	}{
		{
			name:   "empty stderr",
			stderr: "",
			want:   "",
		},
		{
			name:   "no context returns stderr as is",
			stderr: "Failed to launch: test error.\r\n",
			want:   "Failed to launch: test error.\r\n",
		},
		{
			name:   "unknown user error with mixed host user creation decisions gets contextualized",
			stderr: "Failed to launch: user: unknown user teleport-test-user-does-not-exist-reexec.\r\n",
			context: &ErrorContext{
				Login: "teleport-test-user-does-not-exist-reexec",
				DecisionContext: &decisionpb.SSHAccessPermitContext{
					HostUserCreationAllowedBy: []*decisionpb.Determinant{
						{Kind: "role", Name: "allow-role"},
					},
					HostUserCreationDeniedBy: []*decisionpb.Determinant{
						{Kind: "role", Name: "deny-role"},
					},
				},
			},
			want: "Failed to launch: user: unknown user teleport-test-user-does-not-exist-reexec: host user creation denied by the following resources: [role: \"deny-role\"]\r\n",
		},
		{
			name:   "pam context error for unknown user gets contextualized",
			stderr: "Failed to launch: failed to open PAM context: pam_start failed.\r\n",
			context: &ErrorContext{
				Login: "teleport-test-user-does-not-exist-pam",
				DecisionContext: &decisionpb.SSHAccessPermitContext{
					HostUserCreationAllowedBy: []*decisionpb.Determinant{
						{Kind: "role", Name: "allow-role"},
					},
					HostUserCreationDeniedBy: []*decisionpb.Determinant{
						{Kind: "role", Name: "deny-role"},
					},
				},
			},
			want: "Failed to launch: failed to open PAM context: pam_start failed: host user creation denied by the following resources: [role: \"deny-role\"]\r\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := ReadChildError(strings.NewReader(tt.stderr), tt.context)
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}
