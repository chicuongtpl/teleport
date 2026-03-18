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

package app

import (
	"bytes"
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/uuid"
	"github.com/gravitational/trace"
	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/require"

	"github.com/gravitational/teleport/api/types"
	apievents "github.com/gravitational/teleport/api/types/events"
	apiutils "github.com/gravitational/teleport/api/utils"
	"github.com/gravitational/teleport/api/utils/keys"
	"github.com/gravitational/teleport/lib/auth/authclient"
	"github.com/gravitational/teleport/lib/cryptosuites"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/events"
	"github.com/gravitational/teleport/lib/reversetunnelclient"
	"github.com/gravitational/teleport/lib/tlsca"
	"github.com/gravitational/teleport/lib/utils"
)

type eventCheckFn func(t *testing.T, events []apievents.AuditEvent)

func hasAuditEvent(idx int, want apievents.AuditEvent) eventCheckFn {
	return func(t *testing.T, events []apievents.AuditEvent) {
		t.Helper()
		require.Greater(t, len(events), idx)
		require.Empty(t, cmp.Diff(want, events[idx],
			cmpopts.IgnoreFields(apievents.AuthAttempt{}, "ConnectionMetadata")))
	}
}

func hasAuditEventCount(want int) eventCheckFn {
	return func(t *testing.T, events []apievents.AuditEvent) {
		t.Helper()
		require.Len(t, events, want)
	}
}

// TestAuthPOST tests the handler of POST /x-teleport-auth.
func TestAuthPOST(t *testing.T) {
	secretToken := "012ac605867e5a7d693cd6f49c7ff0fb"
	cookieID := "cookie-name"
	stateValue := fmt.Sprintf("%s_%s", secretToken, cookieID)
	appCookieValue := "5588e2be54a2834b4f152c56bafcd789f53b15477129d2ab4044e9a3c1bf0f3b"

	fakeClock := clockwork.NewFakeClock()
	clusterName := "test-cluster"
	publicAddr := "app.example.com"
	// Generate CA TLS key and cert with the cluster and application DNS.
	key, cert, err := tlsca.GenerateSelfSignedCA(
		pkix.Name{CommonName: clusterName},
		[]string{publicAddr, apiutils.EncodeClusterName(clusterName)},
		defaults.CATTL,
	)
	require.NoError(t, err)

	tests := []struct {
		desc            string
		sessionError    error
		outStatusCode   int
		makeRequestBody func(types.WebSession) fragmentRequest
		getEventChecks  func(types.WebSession) []eventCheckFn
	}{
		{
			desc: "success",
			makeRequestBody: func(appSession types.WebSession) fragmentRequest {
				return fragmentRequest{
					StateValue:         stateValue,
					CookieValue:        appCookieValue,
					SubjectCookieValue: appSession.GetBearerToken(),
				}
			},
			outStatusCode: http.StatusOK,
			getEventChecks: func(types.WebSession) []eventCheckFn {
				return []eventCheckFn{hasAuditEventCount(0)}
			},
		},
		{
			desc: "missing state token in request",
			makeRequestBody: func(appSession types.WebSession) fragmentRequest {
				return fragmentRequest{
					StateValue:         "",
					CookieValue:        appCookieValue,
					SubjectCookieValue: appSession.GetBearerToken(),
				}
			},
			outStatusCode: http.StatusForbidden,
			getEventChecks: func(types.WebSession) []eventCheckFn {
				return []eventCheckFn{
					hasAuditEventCount(1),
					hasAuditEvent(0, &apievents.AuthAttempt{
						Metadata: apievents.Metadata{
							Type: events.AuthAttemptEvent,
							Code: events.AuthAttemptFailureCode,
						},
						UserMetadata: apievents.UserMetadata{
							User: "unknown",
						},
						Status: apievents.Status{
							Success: false,
							Error:   "Failed app access authentication: state token was not in the expected format",
						},
					}),
				}
			},
		},
		{
			desc: "missing subject session token in request",
			makeRequestBody: func(ws types.WebSession) fragmentRequest {
				return fragmentRequest{
					StateValue:         stateValue,
					CookieValue:        appCookieValue,
					SubjectCookieValue: "",
				}
			},
			outStatusCode: http.StatusForbidden,
			getEventChecks: func(appSession types.WebSession) []eventCheckFn {
				return []eventCheckFn{
					hasAuditEventCount(1),
					hasAuditEvent(0, &apievents.AuthAttempt{
						Metadata: apievents.Metadata{
							Type: events.AuthAttemptEvent,
							Code: events.AuthAttemptFailureCode,
						},
						UserMetadata: apievents.UserMetadata{
							User:  "unknown",
							Login: "testuser",
						},
						Status: apievents.Status{
							Success: false,
							Error:   "Failed app access authentication: subject session token is not set",
						},
					}),
				}
			},
		},
		{
			desc: "subject session token in request does not match",
			makeRequestBody: func(ws types.WebSession) fragmentRequest {
				return fragmentRequest{
					StateValue:         stateValue,
					CookieValue:        appCookieValue,
					SubjectCookieValue: "foobar",
				}
			},
			outStatusCode: http.StatusForbidden,
			getEventChecks: func(appSession types.WebSession) []eventCheckFn {
				return []eventCheckFn{
					hasAuditEventCount(1),
					hasAuditEvent(0, &apievents.AuthAttempt{
						Metadata: apievents.Metadata{
							Type: events.AuthAttemptEvent,
							Code: events.AuthAttemptFailureCode,
						},
						UserMetadata: apievents.UserMetadata{
							Login: appSession.GetUser(),
							User:  "unknown",
						},
						Status: apievents.Status{
							Success: false,
							Error:   "Failed app access authentication: subject session token does not match",
						},
					}),
				}
			},
		},
		{
			desc: "invalid session",
			makeRequestBody: func(appSession types.WebSession) fragmentRequest {
				return fragmentRequest{
					StateValue:         stateValue,
					CookieValue:        appCookieValue,
					SubjectCookieValue: appSession.GetBearerToken(),
				}
			},
			sessionError:  trace.NotFound("invalid session"),
			outStatusCode: http.StatusForbidden,
			getEventChecks: func(types.WebSession) []eventCheckFn {
				return []eventCheckFn{hasAuditEventCount(0)}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()
			appSession := createAppSession(t, fakeClock, key, cert, clusterName, publicAddr)
			authClient := &mockAuthClient{
				sessionError: test.sessionError,
				appSession:   appSession,
			}
			p := setup(t, fakeClock, authClient, nil)

			reqBody := test.makeRequestBody(appSession)
			req, err := json.Marshal(reqBody)
			require.NoError(t, err)

			status, _ := p.makeRequest(t, "POST", "/x-teleport-auth", req, []http.Cookie{{
				Name:  fmt.Sprintf("%s_%s", AuthStateCookieName, cookieID),
				Value: secretToken,
			}})
			require.Equal(t, status, test.outStatusCode)
			for _, check := range test.getEventChecks(appSession) {
				check(t, authClient.emittedEvents)
			}
		})
	}
}

// dbscTestPack contains common test fixtures for DBSC tests.
type dbscTestPack struct {
	clock      clockwork.Clock
	appSession types.WebSession
	authClient *mockAuthClient
	proxy      *testServer
	client     *http.Client
}

func setupDBSCTest(t *testing.T) *dbscTestPack {
	t.Helper()
	fakeClock := clockwork.NewFakeClock()
	clusterName := "test-cluster"
	publicAddr := "app.example.com"
	key, cert, err := tlsca.GenerateSelfSignedCA(
		pkix.Name{CommonName: clusterName},
		[]string{publicAddr, apiutils.EncodeClusterName(clusterName)},
		defaults.CATTL,
	)
	require.NoError(t, err)

	appSession := createAppSession(t, fakeClock, key, cert, clusterName, publicAddr)
	authClient := &mockAuthClient{appSession: appSession}
	p := setup(t, fakeClock, authClient, nil)
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}

	return &dbscTestPack{
		clock:      fakeClock,
		appSession: appSession,
		authClient: authClient,
		proxy:      p,
		client:     client,
	}
}

// registerDBSCSession performs DBSC registration and returns the private key for refresh proofs.
func (p *dbscTestPack) registerDBSCSession(t *testing.T) crypto.Signer {
	t.Helper()
	challenge, err := createDBSCChallenge(
		p.clock.Now(),
		p.appSession.GetBearerToken(),
		p.appSession.GetName(),
		dbscChallengeKindRegistration,
		DBSCChallengeDefaultTTL,
	)
	require.NoError(t, err)

	privateKey, publicJWK := mustGenerateDBSCKeyPair(t)
	audience := "https://" + p.proxy.serverURL.Host + DBSCRegistrationPath
	proof := mustBuildDBSCRegistrationProofWithKey(t, challenge, audience, privateKey, publicJWK)

	req, err := http.NewRequest(http.MethodPost, "https://"+p.proxy.serverURL.Host+DBSCRegistrationPath, nil)
	require.NoError(t, err)
	req.AddCookie(&http.Cookie{Name: CookieName, Value: p.appSession.GetName()})
	req.AddCookie(&http.Cookie{Name: SubjectCookieName, Value: p.appSession.GetBearerToken()})
	req.Header.Set(SecureSessionResponseHeaderName, proof)

	resp, err := p.client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	return privateKey
}

func TestDBSCRegistration(t *testing.T) {
	t.Parallel()
	p := setupDBSCTest(t)

	// Register and verify response format.
	challenge, err := createDBSCChallenge(
		p.clock.Now(), p.appSession.GetBearerToken(), p.appSession.GetName(),
		dbscChallengeKindRegistration, DBSCChallengeDefaultTTL,
	)
	require.NoError(t, err)

	audience := "https://" + p.proxy.serverURL.Host + DBSCRegistrationPath
	proofJWT, _ := mustBuildDBSCRegistrationProof(t, challenge, audience)

	req, err := http.NewRequest(http.MethodPost, "https://"+p.proxy.serverURL.Host+DBSCRegistrationPath, nil)
	require.NoError(t, err)
	req.AddCookie(&http.Cookie{Name: CookieName, Value: p.appSession.GetName()})
	req.AddCookie(&http.Cookie{Name: SubjectCookieName, Value: p.appSession.GetBearerToken()})
	req.Header.Set(SecureSessionResponseHeaderName, proofJWT)

	resp, err := p.client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// Verify short-lived cookie is set.
	setCookies := resp.Header.Values("Set-Cookie")
	require.Len(t, setCookies, 1)
	require.Contains(t, setCookies[0], "Max-Age=600")

	// Verify response body.
	var response dbscSessionInstructionResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&response))
	require.Equal(t, p.appSession.GetName(), response.SessionIdentifier)
	require.Equal(t, DBSCRefreshPath, response.RefreshURL)
}

func TestDBSCRegistrationRejectsInvalidProof(t *testing.T) {
	t.Parallel()
	p := setupDBSCTest(t)

	req, err := http.NewRequest(http.MethodPost, "https://"+p.proxy.serverURL.Host+DBSCRegistrationPath, nil)
	require.NoError(t, err)
	req.AddCookie(&http.Cookie{Name: CookieName, Value: p.appSession.GetName()})
	req.AddCookie(&http.Cookie{Name: SubjectCookieName, Value: p.appSession.GetBearerToken()})
	req.Header.Set(SecureSessionResponseHeaderName, "invalid-jwt")

	resp, err := p.client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusForbidden, resp.StatusCode)
}

func TestDBSCRefresh(t *testing.T) {
	t.Parallel()
	p := setupDBSCTest(t)
	privateKey := p.registerDBSCSession(t)

	sessionID := fmt.Sprintf(`%q`, p.appSession.GetName())

	// First request without proof gets a challenge.
	refreshReq, err := http.NewRequest(http.MethodPost, "https://"+p.proxy.serverURL.Host+DBSCRefreshPath, nil)
	require.NoError(t, err)
	refreshReq.Header.Set(SecSecureSessionIDHeaderName, sessionID)

	refreshResp, err := p.client.Do(refreshReq)
	require.NoError(t, err)
	defer refreshResp.Body.Close()
	require.Equal(t, http.StatusForbidden, refreshResp.StatusCode)

	challengeHeader := refreshResp.Header.Get(SecureSessionChallengeHeaderName)
	require.NotEmpty(t, challengeHeader)
	challenge, _, err := parseSecureSessionChallengeHeader(challengeHeader)
	require.NoError(t, err)

	// Second request with signed proof succeeds.
	refreshProof := mustBuildDBSCRefreshProof(t, challenge, p.appSession.GetName(),
		"https://"+p.proxy.serverURL.Host+DBSCRefreshPath, privateKey)

	retryReq, err := http.NewRequest(http.MethodPost, "https://"+p.proxy.serverURL.Host+DBSCRefreshPath, nil)
	require.NoError(t, err)
	retryReq.Header.Set(SecSecureSessionIDHeaderName, sessionID)
	retryReq.Header.Set(SecureSessionResponseHeaderName, refreshProof)

	retryResp, err := p.client.Do(retryReq)
	require.NoError(t, err)
	defer retryResp.Body.Close()
	require.Equal(t, http.StatusOK, retryResp.StatusCode)
	require.Contains(t, retryResp.Header.Get("Set-Cookie"), "Max-Age=600")
}

func TestDBSCRefreshRequiresRegistration(t *testing.T) {
	t.Parallel()
	p := setupDBSCTest(t)

	// Try to refresh without registering first.
	req, err := http.NewRequest(http.MethodPost, "https://"+p.proxy.serverURL.Host+DBSCRefreshPath, nil)
	require.NoError(t, err)
	req.Header.Set(SecSecureSessionIDHeaderName, fmt.Sprintf(`%q`, p.appSession.GetName()))

	resp, err := p.client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusForbidden, resp.StatusCode)
	require.Empty(t, resp.Header.Get(SecureSessionChallengeHeaderName))
}

func TestHasName(t *testing.T) {
	for _, test := range []struct {
		desc        string
		addrs       []string
		reqHost     string
		reqURL      string
		expectedURL string
		hasName     bool
	}{
		{
			desc:        "NOK - invalid host",
			addrs:       []string{"proxy.com"},
			reqURL:      "badurl.com",
			expectedURL: "",
			hasName:     false,
		},
		{
			desc:        "OK - adds path",
			addrs:       []string{"proxy.com"},
			reqURL:      "https://app1.proxy.com/foo",
			expectedURL: "https://proxy.com/web/launch/app1.proxy.com?path=%2Ffoo",
			hasName:     true,
		},
		{
			desc:        "OK - adds paths with ampersands",
			addrs:       []string{"proxy.com"},
			reqURL:      "https://app1.proxy.com/foo/this&/that",
			expectedURL: "https://proxy.com/web/launch/app1.proxy.com?path=%2Ffoo%2Fthis%26%2Fthat",
			hasName:     true,
		},
		{
			desc:        "OK - adds root path",
			addrs:       []string{"proxy.com"},
			reqURL:      "https://app1.proxy.com/",
			expectedURL: "https://proxy.com/web/launch/app1.proxy.com?path=%2F",
			hasName:     true,
		},
	} {
		t.Run(test.desc, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet, test.reqURL, nil)
			require.NoError(t, err)

			addrs := utils.MustParseAddrList(test.addrs...)
			u, ok := HasName(req, addrs)
			require.Equal(t, test.expectedURL, u)
			require.Equal(t, test.hasName, ok)
		})
	}
}

func TestMatchApplicationServers(t *testing.T) {
	clusterName := "test-cluster"
	publicAddr := "app.example.com"

	// Generate CA TLS key and cert with the cluster and application DNS.
	key, cert, err := tlsca.GenerateSelfSignedCA(
		pkix.Name{CommonName: clusterName},
		[]string{publicAddr, apiutils.EncodeClusterName(clusterName)},
		defaults.CATTL,
	)
	require.NoError(t, err)

	fakeClock := clockwork.NewFakeClock()
	authClient := &mockAuthClient{
		clusterName: clusterName,
		appSession:  createAppSession(t, fakeClock, key, cert, clusterName, publicAddr),
		// Three app servers with same public addr from our session, and three
		// that won't match.
		appServers: []types.AppServer{
			createAppServer(t, publicAddr),
			createAppServer(t, publicAddr),
			createAppServer(t, publicAddr),
			createAppServer(t, "random.example.com"),
			createAppServer(t, "random2.example.com"),
			createAppServer(t, "random3.example.com"),
		},
		caKey:  key,
		caCert: cert,
	}

	// Create a httptest server to serve the application requests. It must serve
	// TLS content with the generated certificate.
	expectedContent := "Hello application"
	fakeCluster := startFakeAppServerOnCluster(t, clusterName, authClient, cert, key)
	tunnel := &reversetunnelclient.FakeServer{
		FakeClusters: []reversetunnelclient.Cluster{
			fakeCluster,
		},
	}

	p := setup(t, fakeClock, authClient, tunnel)
	status, content := p.makeRequest(t, "GET", "/", []byte{}, []http.Cookie{
		{
			Name:  CookieName,
			Value: "abc",
		},
		{
			Name:  SubjectCookieName,
			Value: authClient.appSession.GetBearerToken(),
		},
	})

	require.Equal(t, http.StatusOK, status)
	// Cluster should receive only 4 connection requests: 3 from the
	// MatchHealthy and 1 from the transport.
	require.Equal(t, int64(4), fakeCluster.DialCount())
	// Guarantee the request was returned by the httptest server.
	require.Equal(t, expectedContent, content)
}

func TestHealthCheckAppServer(t *testing.T) {
	ctx := context.Background()
	clusterName := "test-cluster"
	publicAddr := "valid.example.com"

	key, cert, err := tlsca.GenerateSelfSignedCA(
		pkix.Name{CommonName: clusterName},
		[]string{publicAddr, apiutils.EncodeClusterName(clusterName)},
		defaults.CATTL,
	)
	require.NoError(t, err)

	for _, tc := range []struct {
		desc                string
		publicAddr          string
		appServersFunc      func(t *testing.T, cluster *reversetunnelclient.FakeCluster) []types.AppServer
		expectedTunnelCalls int
		expectErr           require.ErrorAssertionFunc
	}{
		{
			desc:       "match and online services",
			publicAddr: "valid.example.com",
			appServersFunc: func(t *testing.T, _ *reversetunnelclient.FakeCluster) []types.AppServer {
				return []types.AppServer{createAppServer(t, "valid.example.com")}
			},
			expectedTunnelCalls: 1,
			expectErr:           require.NoError,
		},
		{
			desc:       "match and but no online services",
			publicAddr: "valid.example.com",
			appServersFunc: func(t *testing.T, cluster *reversetunnelclient.FakeCluster) []types.AppServer {
				appServer := createAppServer(t, "valid.example.com")
				cluster.OfflineTunnels = map[string]struct{}{
					fmt.Sprintf("%s.%s", appServer.GetHostID(), clusterName): {},
				}
				return []types.AppServer{appServer}
			},
			expectedTunnelCalls: 1,
			expectErr:           require.Error,
		},
		{
			desc:       "no match",
			publicAddr: "valid.example.com",
			appServersFunc: func(t *testing.T, _ *reversetunnelclient.FakeCluster) []types.AppServer {
				return []types.AppServer{}
			},
			expectedTunnelCalls: 0,
			expectErr:           require.Error,
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			fakeClock := clockwork.NewFakeClock()
			appSession := createAppSession(t, fakeClock, key, cert, clusterName, publicAddr)
			authClient := &mockAuthClient{
				clusterName: clusterName,
				appSession:  appSession,
				caKey:       key,
				caCert:      cert,
			}

			fakeCluster := startFakeAppServerOnCluster(t, clusterName, authClient, cert, key)
			authClient.appServers = tc.appServersFunc(t, fakeCluster)

			tunnel := &reversetunnelclient.FakeServer{
				FakeClusters: []reversetunnelclient.Cluster{fakeCluster},
			}

			appHandler, err := NewHandler(ctx, &HandlerConfig{
				Clock:                 fakeClock,
				AuthClient:            authClient,
				AccessPoint:           authClient,
				ClusterGetter:         tunnel,
				CipherSuites:          utils.DefaultCipherSuites(),
				IntegrationAppHandler: &mockIntegrationAppHandler{},
			})
			require.NoError(t, err)

			err = appHandler.HealthCheckAppServer(ctx, tc.publicAddr, clusterName)
			tc.expectErr(t, err)
			require.Equal(t, int64(tc.expectedTunnelCalls), fakeCluster.DialCount())
		})
	}
}

type testServer struct {
	serverURL *url.URL
}

func setup(t *testing.T, clock *clockwork.FakeClock, authClient authclient.ClientI, clusterGetter reversetunnelclient.ClusterGetter) *testServer {
	appHandler, err := NewHandler(context.Background(), &HandlerConfig{
		Clock:                 clock,
		AuthClient:            authClient,
		AccessPoint:           authClient,
		ClusterGetter:         clusterGetter,
		CipherSuites:          utils.DefaultCipherSuites(),
		IntegrationAppHandler: &mockIntegrationAppHandler{},
	})
	require.NoError(t, err)

	server := httptest.NewUnstartedServer(appHandler)
	server.StartTLS()

	url, err := url.Parse(server.URL)
	require.NoError(t, err)

	return &testServer{
		serverURL: url,
	}
}

func (p *testServer) makeRequest(t *testing.T, method, endpoint string, reqBody []byte, cookies []http.Cookie) (int, string) {
	u := url.URL{
		Scheme: p.serverURL.Scheme,
		Host:   p.serverURL.Host,
		Path:   endpoint,
	}
	req, err := http.NewRequest(http.MethodPost, u.String(), bytes.NewBuffer(reqBody))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")

	// Attach the cookie.
	for _, c := range cookies {
		req.AddCookie(&c)
	}

	// Issue request.
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Do(req)
	require.NoError(t, err)

	content, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	require.NoError(t, resp.Body.Close())
	return resp.StatusCode, string(content)
}

type mockAuthClient struct {
	authclient.ClientI
	clusterName             string
	appSession              types.WebSession
	sessionError            error
	invalidateSessionDelete bool
	appServers              []types.AppServer
	caKey                   []byte
	caCert                  []byte
	emittedEvents           []apievents.AuditEvent
	mtx                     sync.Mutex
}

type mockClusterName struct {
	types.ClusterName
	name string
}

func (c *mockAuthClient) EmitAuditEvent(ctx context.Context, event apievents.AuditEvent) error {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	c.emittedEvents = append(c.emittedEvents, event)
	return nil
}

func (c *mockAuthClient) DeleteAppSession(ctx context.Context, r types.DeleteAppSessionRequest) error {
	c.mtx.Lock()
	defer c.mtx.Unlock()

	if c.invalidateSessionDelete && c.appSession != nil && c.appSession.GetName() == r.SessionID {
		c.appSession = nil
	}
	return nil
}

func (c *mockAuthClient) GetClusterName(_ context.Context) (types.ClusterName, error) {
	return mockClusterName{name: c.clusterName}, nil
}

func (n mockClusterName) GetClusterName() string {
	if n.name != "" {
		return n.name
	}

	return "local-cluster"
}

func (c *mockAuthClient) GetAppSession(_ context.Context, _ types.GetAppSessionRequest) (types.WebSession, error) {
	c.mtx.Lock()
	defer c.mtx.Unlock()

	if c.sessionError != nil {
		return nil, c.sessionError
	}
	if c.appSession == nil {
		return nil, trace.NotFound("app session not found")
	}
	return c.appSession, nil
}

func (c *mockAuthClient) UpsertAppSession(_ context.Context, session types.WebSession) error {
	c.mtx.Lock()
	defer c.mtx.Unlock()

	c.appSession = session
	return nil
}

func (c *mockAuthClient) GetApplicationServers(_ context.Context, _ string) ([]types.AppServer, error) {
	return c.appServers, nil
}

func (c *mockAuthClient) GetCertAuthority(ctx context.Context, id types.CertAuthID, loadKeys bool) (types.CertAuthority, error) {
	ca, err := types.NewCertAuthority(types.CertAuthoritySpecV2{
		Type:        types.HostCA,
		ClusterName: c.clusterName,
		ActiveKeys: types.CAKeySet{
			TLS: []*types.TLSKeyPair{{
				Cert: c.caCert,
				Key:  c.caKey,
			}},
		},
	})
	if err != nil {
		return nil, err
	}

	return ca, nil
}

func (c *mockAuthClient) NewWatcher(context.Context, types.Watch) (types.Watcher, error) {
	return nil, trace.NotImplemented("")
}

func (c *mockAuthClient) GetProxies() ([]types.Server, error) {
	return []types.Server{}, nil
}

func (c *mockAuthClient) ListProxyServers(context.Context, int, string) ([]types.Server, string, error) {
	return []types.Server{}, "", nil
}

// fakeClusterListener Implements a `net.Listener` that return `net.Conn` from
// the `FakeCluster`.
type fakeClusterListener struct {
	fakeCluster *reversetunnelclient.FakeCluster
}

func (r *fakeClusterListener) Accept() (net.Conn, error) {
	conn, ok := <-r.fakeCluster.ProxyConn()
	if !ok {
		return nil, fmt.Errorf("cluster closed")
	}

	return conn, nil
}

func (r *fakeClusterListener) Close() error {
	return nil
}

func (r *fakeClusterListener) Addr() net.Addr {
	return &net.IPAddr{}
}

// createAppSession generates a WebSession for an application.
func createAppSession(t *testing.T, clock *clockwork.FakeClock, caKey, caCert []byte, clusterName, publicAddr string) types.WebSession {
	key, cert := createAppKeyCertPair(t, clock, caKey, caCert, clusterName, publicAddr)
	keyPEM, err := keys.MarshalPrivateKey(key)
	require.NoError(t, err)
	appSession, err := types.NewWebSession(uuid.New().String(), types.KindAppSession, types.WebSessionSpecV2{
		User:        "testuser",
		TLSPriv:     keyPEM,
		TLSCert:     cert,
		Expires:     clock.Now().Add(5 * time.Minute),
		BearerToken: "abc123",
	})
	require.NoError(t, err)

	return appSession
}

func mustGenerateDBSCKeyPair(t *testing.T) (crypto.Signer, jose.JSONWebKey) {
	t.Helper()

	privateKey, err := cryptosuites.GenerateKeyWithAlgorithm(cryptosuites.ECDSAP256)
	require.NoError(t, err)

	publicJWK := jose.JSONWebKey{
		Algorithm: string(jose.ES256),
		Key:       privateKey.Public(),
		Use:       "sig",
	}
	return privateKey, publicJWK
}

func mustBuildDBSCRegistrationProof(t *testing.T, challenge, audience string) (string, jose.JSONWebKey) {
	privateKey, publicJWK := mustGenerateDBSCKeyPair(t)
	return mustBuildDBSCRegistrationProofWithKey(t, challenge, audience, privateKey, publicJWK), publicJWK
}

func mustBuildDBSCRegistrationProofWithKey(t *testing.T, challenge, audience string, privateKey crypto.Signer, publicJWK jose.JSONWebKey) string {
	t.Helper()

	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: privateKey},
		(&jose.SignerOptions{}).WithType(dbscProofJWTType),
	)
	require.NoError(t, err)

	token, err := jwt.Signed(signer).Claims(dbscRegistrationProofClaims{
		JTI: challenge,
		JWK: &publicJWK,
		Aud: []string{audience},
	}).Serialize()
	require.NoError(t, err)

	return token
}

func mustBuildDBSCRefreshProof(t *testing.T, challenge, sessionIdentifier, audience string, privateKey crypto.Signer) string {
	t.Helper()
	publicJWK := jose.JSONWebKey{
		Algorithm: string(jose.ES256),
		Key:       privateKey.Public(),
		Use:       "sig",
	}
	return mustBuildDBSCRefreshProofWithJWK(t, challenge, sessionIdentifier, audience, privateKey, publicJWK)
}

func mustBuildDBSCRefreshProofWithJWK(t *testing.T, challenge, sessionIdentifier, audience string, privateKey crypto.Signer, publicJWK jose.JSONWebKey) string {
	t.Helper()

	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: privateKey},
		(&jose.SignerOptions{}).WithType(dbscProofJWTType).WithHeader(jose.HeaderKey("jwk"), publicJWK),
	)
	require.NoError(t, err)

	token, err := jwt.Signed(signer).Claims(jwt.Claims{
		ID:       challenge,
		Subject:  sessionIdentifier,
		Audience: jwt.Audience{audience},
		IssuedAt: jwt.NewNumericDate(time.Now()),
		Expiry:   jwt.NewNumericDate(time.Now().Add(time.Minute)),
	}).Serialize()
	require.NoError(t, err)

	return token
}

// createAppKeyCertPair creates and a client key and signed app cert for the client key
func createAppKeyCertPair(t *testing.T, clock *clockwork.FakeClock, caKey, caCert []byte, clusterName, publicAddr string) (crypto.Signer, []byte) {
	tlsCA, err := tlsca.FromKeys(caCert, caKey)
	require.NoError(t, err)

	privateKey, err := cryptosuites.GenerateKeyWithAlgorithm(cryptosuites.ECDSAP256)
	require.NoError(t, err)

	// Generate the identity with a `RouteToApp` option.
	subj, err := (&tlsca.Identity{
		Username: "testuser",
		Groups:   []string{"access"},
		RouteToApp: tlsca.RouteToApp{
			PublicAddr:  publicAddr,
			ClusterName: clusterName,
			Name:        "testapp",
		},
	}).Subject()
	require.NoError(t, err)

	cert, err := tlsCA.GenerateCertificate(tlsca.CertificateRequest{
		Clock:     clock,
		PublicKey: privateKey.Public(),
		Subject:   subj,
		NotAfter:  clock.Now().Add(5 * time.Minute),
	})
	require.NoError(t, err)

	return privateKey, cert
}

func createAppServer(t *testing.T, publicAddr string) types.AppServer {
	appName := uuid.New().String()
	appServer, err := types.NewAppServerV3(
		types.Metadata{Name: appName},
		types.AppServerSpecV3{
			HostID: uuid.New().String(),
			App: &types.AppV3{
				Metadata: types.Metadata{Name: appName},
				Spec: types.AppSpecV3{
					URI:        "localhost",
					PublicAddr: publicAddr,
				},
			},
		},
	)
	require.NoError(t, err)
	return appServer
}

func TestMakeAppRedirectURL(t *testing.T) {
	for _, test := range []struct {
		name             string
		reqURL           string
		expectedURL      string
		launderURLParams launcherURLParams
	}{
		// with launcherURLParams empty (will be empty if user did not launch app from our web UI)
		{
			name:        "OK - no path",
			reqURL:      "https://grafana.localhost",
			expectedURL: "https://proxy.com/web/launch/grafana.localhost?path=",
		},
		{
			name:        "OK - add root path",
			reqURL:      "https://grafana.localhost/",
			expectedURL: "https://proxy.com/web/launch/grafana.localhost?path=%2F",
		},
		{
			name:        "OK - add multi path",
			reqURL:      "https://grafana.localhost/foo/bar",
			expectedURL: "https://proxy.com/web/launch/grafana.localhost?path=%2Ffoo%2Fbar",
		},
		{
			name:        "OK - add paths with ampersands",
			reqURL:      "https://grafana.localhost/foo/this&/that",
			expectedURL: "https://proxy.com/web/launch/grafana.localhost?path=%2Ffoo%2Fthis%26%2Fthat",
		},
		{
			name:        "OK - add only query",
			reqURL:      "https://grafana.localhost?foo=bar",
			expectedURL: "https://proxy.com/web/launch/grafana.localhost?path=&query=foo%3Dbar",
		},
		{
			name:        "OK - add query with same keys used to store the original path and query",
			reqURL:      "https://grafana.localhost?foo=bar&query=test1&path=test",
			expectedURL: "https://proxy.com/web/launch/grafana.localhost?path=&query=foo%3Dbar%26query%3Dtest1%26path%3Dtest",
		},
		{
			name:        "OK - adds query with root path",
			reqURL:      "https://grafana.localhost/?foo=bar&baz=qux&fruit=apple",
			expectedURL: "https://proxy.com/web/launch/grafana.localhost?path=%2F&query=foo%3Dbar%26baz%3Dqux%26fruit%3Dapple",
		},
		{
			name:        "OK - real grafana query example (encoded spaces)",
			reqURL:      "https://grafana.localhost/alerting/list?search=state:inactive%20type:alerting%20health:nodata",
			expectedURL: "https://proxy.com/web/launch/grafana.localhost?path=%2Falerting%2Flist&query=search%3Dstate%3Ainactive%2520type%3Aalerting%2520health%3Anodata",
		},
		{
			name:        "OK - query with non-encoded spaces",
			reqURL:      "https://grafana.localhost/alerting /list?search=state:inactive type:alerting health:nodata",
			expectedURL: "https://proxy.com/web/launch/grafana.localhost?path=%2Falerting+%2Flist&query=search%3Dstate%3Ainactive+type%3Aalerting+health%3Anodata",
		},

		// with launcherURLParams (defined if user used the "launcher" button from our web UI)
		{
			name: "OK - with clusterId and publicAddr",
			launderURLParams: launcherURLParams{
				stateToken:  "abc123",
				clusterName: "im-a-cluster-name",
				publicAddr:  "grafana.localhost",
			},
			expectedURL: "https://proxy.com/web/launch/grafana.localhost/im-a-cluster-name/grafana.localhost?path=&required-apps=&state=abc123",
		},
		{
			name: "OK - with clusterId, publicAddr, and arn",
			launderURLParams: launcherURLParams{
				stateToken:  "abc123",
				clusterName: "im-a-cluster-name",
				publicAddr:  "grafana.localhost",
				arn:         "arn:aws:iam::123456789012:role%2Frole-name",
			},
			expectedURL: "https://proxy.com/web/launch/grafana.localhost/im-a-cluster-name/grafana.localhost/arn:aws:iam::123456789012:role%252Frole-name?path=&required-apps=&state=abc123",
		},
		{
			name: "OK - with clusterId, publicAddr, arn and path",
			launderURLParams: launcherURLParams{
				stateToken:  "abc123",
				clusterName: "im-a-cluster-name",
				publicAddr:  "grafana.localhost",
				arn:         "arn:aws:iam::123456789012:role%2Frole-name",
				path:        "/foo/bar?qux=qex",
			},
			expectedURL: "https://proxy.com/web/launch/grafana.localhost/im-a-cluster-name/grafana.localhost/arn:aws:iam::123456789012:role%252Frole-name?path=%2Ffoo%2Fbar%3Fqux%3Dqex&required-apps=&state=abc123",
		},
		{
			name: "OK - with clusterId, publicAddr, arn, path, and required-apps",
			launderURLParams: launcherURLParams{
				stateToken:       "abc123",
				clusterName:      "im-a-cluster-name",
				publicAddr:       "grafana.localhost",
				arn:              "arn:aws:iam::123456789012:role%2Frole-name",
				path:             "/foo/bar?qux=qex",
				requiredAppFQDNs: "api.example.com,grafana.localhost",
			},
			expectedURL: "https://proxy.com/web/launch/grafana.localhost/im-a-cluster-name/grafana.localhost/arn:aws:iam::123456789012:role%252Frole-name?path=%2Ffoo%2Fbar%3Fqux%3Dqex&required-apps=api.example.com%2Cgrafana.localhost&state=abc123",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet, test.reqURL, nil)
			require.NoError(t, err)

			urlStr := makeAppRedirectURL(req, "proxy.com", "grafana.localhost", test.launderURLParams)
			require.Equal(t, test.expectedURL, urlStr)
		})
	}
}

func startFakeAppServerOnCluster(t *testing.T, clusterName string, accessPoint authclient.RemoteProxyAccessPoint, cert, key []byte) *reversetunnelclient.FakeCluster {
	t.Helper()

	tlsCert, err := tls.X509KeyPair(cert, key)
	require.NoError(t, err)

	fakeCluster := reversetunnelclient.NewFakeCluster(clusterName, accessPoint)
	server := &httptest.Server{
		TLS: &tls.Config{
			Certificates: []tls.Certificate{tlsCert},
		},
		Listener: &fakeClusterListener{
			fakeCluster: fakeCluster,
		},
		Config: &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			fmt.Fprint(w, "Hello application")
		})},
	}
	server.StartTLS()
	t.Cleanup(func() {
		// Close fake cluster first to make sure fake listener quits.
		fakeCluster.Close()
		server.Close()
	})
	return fakeCluster
}

func TestHandlerAuthenticate(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	clusterName := "test-cluster"
	publicAddr := "app.example.com"
	key, cert, err := tlsca.GenerateSelfSignedCA(
		pkix.Name{CommonName: clusterName},
		[]string{publicAddr, apiutils.EncodeClusterName(clusterName)},
		defaults.CATTL,
	)
	require.NoError(t, err)
	fakeClock := clockwork.NewFakeClock()

	authClient := &mockAuthClient{
		clusterName: clusterName,
		appSession:  createAppSession(t, fakeClock, key, cert, clusterName, publicAddr),
		appServers: []types.AppServer{
			createAppServer(t, publicAddr),
		},
		caKey:  key,
		caCert: cert,
	}

	fakeCluster := startFakeAppServerOnCluster(t, clusterName, authClient, cert, key)

	appHandler, err := NewHandler(ctx, &HandlerConfig{
		Clock:       fakeClock,
		AuthClient:  authClient,
		AccessPoint: authClient,
		ClusterGetter: &reversetunnelclient.FakeServer{
			FakeClusters: []reversetunnelclient.Cluster{fakeCluster},
		},
		CipherSuites:          utils.DefaultCipherSuites(),
		IntegrationAppHandler: &mockIntegrationAppHandler{},
	})
	require.NoError(t, err)

	t.Run("with cookie", func(t *testing.T) {
		request := httptest.NewRequest("GET", "https://"+publicAddr, nil)
		addValidSessionCookiesToRequest(authClient.appSession, request)

		_, err = appHandler.authenticate(ctx, request)
		require.NoError(t, err)
	})

	t.Run("with client cert", func(t *testing.T) {
		clientCert, err := tls.X509KeyPair(authClient.appSession.GetTLSCert(), authClient.appSession.GetTLSPriv())
		require.NoError(t, err)
		require.NotEmpty(t, clientCert.Certificate)
		x509Cert, err := x509.ParseCertificate(clientCert.Certificate[0])
		require.NoError(t, err)

		request := httptest.NewRequest("GET", "https://"+publicAddr, nil)
		request.TLS.PeerCertificates = []*x509.Certificate{x509Cert}

		_, err = appHandler.authenticate(ctx, request)
		require.NoError(t, err)
	})

	t.Run("without cookie or client cert", func(t *testing.T) {
		request := httptest.NewRequest("GET", "https://"+publicAddr, nil)
		_, err := appHandler.authenticate(ctx, request)
		require.Error(t, err)
		require.True(t, trace.IsAccessDenied(err))
	})

	t.Run("session expired", func(t *testing.T) {
		fakeClock.Advance(authClient.appSession.Expiry().Sub(fakeClock.Now()) + time.Minute)
		request := httptest.NewRequest("GET", "https://"+publicAddr, nil)
		addValidSessionCookiesToRequest(authClient.appSession, request)

		_, err := appHandler.authenticate(ctx, request)
		require.Error(t, err)
		require.True(t, trace.IsAccessDenied(err))
	})
}

func TestRedirectToLauncherClusterFallback(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	clusterName := "tp.test"
	appFQDN := "greeting.tp.test"
	authClient := &mockAuthClient{clusterName: clusterName}

	appHandler, err := NewHandler(ctx, &HandlerConfig{
		AuthClient:            authClient,
		AccessPoint:           authClient,
		CipherSuites:          utils.DefaultCipherSuites(),
		IntegrationAppHandler: &mockIntegrationAppHandler{},
	})
	require.NoError(t, err)

	t.Run("redirects using cluster name when ProxyPublicAddrs is empty", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "https://"+appFQDN+"/", nil)
		err := appHandler.redirectToLauncher(w, r, launcherURLParams{stateToken: "tok"})
		require.NoError(t, err)
		require.Equal(t, http.StatusFound, w.Code)
		loc := w.Header().Get("Location")
		want := "https://" + clusterName + ":443/web/launch/" + appFQDN
		require.True(t, strings.HasPrefix(loc, want), "got %s, want prefix %s", loc, want)
	})

	t.Run("rejects app addr matching cluster name", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "https://"+clusterName+"/", nil)
		err := appHandler.redirectToLauncher(w, r, launcherURLParams{stateToken: "tok", publicAddr: clusterName})
		require.Error(t, err)
		require.True(t, trace.IsBadParameter(err))
	})

	t.Run("preserves request port in fallback redirect", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "https://"+appFQDN+":3080/", nil)
		err := appHandler.redirectToLauncher(w, r, launcherURLParams{stateToken: "tok"})
		require.NoError(t, err)
		loc := w.Header().Get("Location")
		want := "https://" + clusterName + ":3080/web/launch/" + appFQDN
		require.True(t, strings.HasPrefix(loc, want), "got %s, want prefix %s", loc, want)
	})
}

func addValidSessionCookiesToRequest(appSession types.WebSession, r *http.Request) {
	r.AddCookie(&http.Cookie{
		Name:  CookieName,
		Value: appSession.GetName(),
	})
	r.AddCookie(&http.Cookie{
		Name:  SubjectCookieName,
		Value: appSession.GetBearerToken(),
	})
}
