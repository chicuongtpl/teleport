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

package eventstest

import (
	"context"

	apievents "github.com/gravitational/teleport/api/types/events"
	"github.com/gravitational/teleport/lib/events"
	"github.com/gravitational/teleport/lib/session"
)

type MockAuditLog struct {
	*events.DiscardAuditLog

	Emitter           *MockRecorderEmitter
	SessionEvents     []apievents.AuditEvent
	TempSessionEvents []apievents.AuditEvent
}

func (m *MockAuditLog) streamEvents(ctx context.Context, sid session.ID, useTemp bool, startIndex int64) (chan apievents.AuditEvent, chan error) {
	errors := make(chan error, 1)
	events := make(chan apievents.AuditEvent)
	srcEvents := m.SessionEvents
	if useTemp {
		srcEvents = m.TempSessionEvents
	}
	go func() {
		defer close(events)

		for _, event := range srcEvents {
			if event.GetIndex() >= startIndex {
				select {
				case <-ctx.Done():
					return
				case events <- event:
				}
			} else {
			}
		}
	}()

	return events, errors
}

func (m *MockAuditLog) StreamSessionEvents(ctx context.Context, sid session.ID, startIndex int64) (chan apievents.AuditEvent, chan error) {
	return m.streamEvents(ctx, sid, false, startIndex)
}

func (m *MockAuditLog) StreamUploadEvents(ctx context.Context, sid session.ID, uploadID string, startIndex int64) (chan apievents.AuditEvent, chan error) {
	return m.streamEvents(ctx, sid, uploadID != "", startIndex)
}

func (m *MockAuditLog) EmitAuditEvent(ctx context.Context, event apievents.AuditEvent) error {
	return m.Emitter.EmitAuditEvent(ctx, event)
}
