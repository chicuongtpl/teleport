/*
 * Teleport
 * Copyright (C) 2023  Gravitational, Inc.
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

package common

import (
	"bytes"
	"reflect"
	"testing"
	"unsafe"

	"github.com/gravitational/trace"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"github.com/gravitational/teleport/lib/client"
	toolcommon "github.com/gravitational/teleport/tool/common"
)

func TestConvertSSHExitCodeSSHExitErrorMessages(t *testing.T) {
	tests := []struct {
		name       string
		inputErr   error
		wantStderr bool
	}{
		{
			name:       "plain exit status is suppressed",
			inputErr:   trace.Wrap(newSSHExitError(20, "", "")),
			wantStderr: false,
		},
		{
			name:       "exit signal is printed",
			inputErr:   trace.Wrap(newSSHExitError(20, "TERM", "")),
			wantStderr: true,
		},
		{
			name:       "exit message is printed",
			inputErr:   trace.Wrap(newSSHExitError(20, "", "killed by policy")),
			wantStderr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stderr bytes.Buffer
			tc := &client.TeleportClient{
				Config: client.Config{
					Stderr: &stderr,
				},
			}
			tc.SetExitStatus(20)

			err := convertSSHExitCode(tc, tt.inputErr)
			require.Error(t, err)

			var exitErr *toolcommon.ExitCodeError
			require.ErrorAs(t, err, &exitErr)
			require.Equal(t, 20, exitErr.Code)
			if tt.wantStderr {
				require.NotEmpty(t, stderr.String())
			} else {
				require.Empty(t, stderr.String())
			}
		})
	}
}

func newSSHExitError(status int, signal, msg string) *ssh.ExitError {
	exitErr := &ssh.ExitError{}
	waitMsg := reflect.ValueOf(exitErr).Elem().FieldByName("Waitmsg")
	setUnexportedInt(waitMsg.FieldByName("status"), int64(status))
	setUnexportedString(waitMsg.FieldByName("signal"), signal)
	setUnexportedString(waitMsg.FieldByName("msg"), msg)
	return exitErr
}

func setUnexportedInt(v reflect.Value, n int64) {
	reflect.NewAt(v.Type(), unsafe.Pointer(v.UnsafeAddr())).Elem().SetInt(n)
}

func setUnexportedString(v reflect.Value, s string) {
	reflect.NewAt(v.Type(), unsafe.Pointer(v.UnsafeAddr())).Elem().SetString(s)
}
