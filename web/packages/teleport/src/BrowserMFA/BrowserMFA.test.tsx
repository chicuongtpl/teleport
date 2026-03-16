/**
 * Teleport
 * Copyright (C) 2026 Gravitational, Inc.
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

import { createMemoryRouter, RouterProvider } from 'react-router';

import { render, screen, waitFor } from 'design/utils/testing';

import { BrowserMFA } from 'teleport/BrowserMFA/BrowserMFA';
import { validateClientRedirect } from 'teleport/BrowserMFA/urlValidation';
import cfg from 'teleport/config';
import { shouldShowMfaPrompt } from 'teleport/lib/useMfa';
import auth from 'teleport/services/auth';

const mockGetChallengeResponse = jest.fn();

jest.mock('teleport/lib/useMfa', () => ({
  useMfa: () => ({
    getChallengeResponse: mockGetChallengeResponse,
    attempt: { status: '' },
  }),
  shouldShowMfaPrompt: jest.fn(),
}));

jest.mock('teleport/BrowserMFA/urlValidation', () => ({
  validateClientRedirect: jest.fn((url: string) => url),
}));

type SetupOptions = {
  showMFAPrompt?: boolean;
  path?: string;
  onRedirect?: (url: string) => void;
  browserMfaPutResponse?: Promise<string>;
  validateRedirect?: (url: string) => string;
};

function setup({
  showMFAPrompt = false,
  path = '/web/mfa/browser/12345',
  onRedirect = jest.fn(),
  browserMfaPutResponse = Promise.resolve(
    'http://localhost:12345?response=abc'
  ),
  validateRedirect = (url: string) => url,
}: SetupOptions = {}) {
  (shouldShowMfaPrompt as jest.Mock).mockReturnValue(showMFAPrompt);
  (validateClientRedirect as jest.Mock).mockImplementation(validateRedirect);

  mockGetChallengeResponse.mockResolvedValue({ webauthn_response: {} });

  jest
    .spyOn(auth, 'browserMFAPut')
    .mockImplementation(() => browserMfaPutResponse);

  const router = createMemoryRouter(
    [
      {
        path: cfg.routes.browserMfa,
        element: <BrowserMFA onRedirect={onRedirect} />,
      },
    ],
    {
      initialEntries: [path],
    }
  );

  render(<RouterProvider router={router} />);
}

describe('BrowserMFA', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  test('shows MFA prompt', async () => {
    setup({ showMFAPrompt: true });

    expect(await screen.findByText('Verify Your Identity')).toBeInTheDocument();
  });

  test('calls auth.browserMFA with the request ID from the URL', async () => {
    const onRedirect = jest.fn();
    setup({ onRedirect });

    await waitFor(() => expect(auth.browserMFAPut).toHaveBeenCalled());

    expect(auth.browserMFAPut).toHaveBeenCalledWith(
      expect.anything(),
      '12345',
      expect.any(AbortSignal)
    );

    expect(onRedirect).toHaveBeenCalledWith(
      'http://localhost:12345?response=abc'
    );
  });

  test('shows loading indicator while processing', async () => {
    const onRedirect = jest.fn();
    const neverResolves = new Promise<string>(() => {});

    setup({ onRedirect, browserMfaPutResponse: neverResolves });

    expect(await screen.findByTestId('indicator')).toBeInTheDocument();
    expect(onRedirect).not.toHaveBeenCalled();
  });

  test('shows access denied when redirect URL is invalid', async () => {
    const onRedirect = jest.fn();

    setup({
      onRedirect,
      validateRedirect: () => {
        throw new Error('Invalid redirect URL');
      },
    });

    expect(await screen.findByText('Invalid redirect URL')).toBeInTheDocument();
    expect(onRedirect).not.toHaveBeenCalled();
  });

  test('shows error when request ID not included', async () => {
    setup({ path: '/web/mfa/browser' });

    expect(await screen.findByText('Missing request ID')).toBeInTheDocument();
    expect(auth.browserMFAPut).not.toHaveBeenCalled();
  });
});
