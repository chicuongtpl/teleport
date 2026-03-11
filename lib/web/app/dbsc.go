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
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/gravitational/trace"

	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/utils"
)

const (
	// SecureSessionRegistrationHeaderName is the registration header defined by
	// DBSC.
	SecureSessionRegistrationHeaderName = "Secure-Session-Registration"
	// DBSCChallengeDefaultTTL is the validity duration for issued challenges.
	DBSCChallengeDefaultTTL = time.Minute
	// SecureSessionResponseHeaderName is the DBSC proof JWT header.
	SecureSessionResponseHeaderName = "Secure-Session-Response"

	dbscRegistrationAlgorithm = "ES256"
	dbscProofJWTType          = "dbsc+jwt"

	dbscChallengeVersion          = 1
	dbscChallengeContextLabel     = "teleport:dbsc:challenge:v1"
	dbscChallengeMaxLen           = 4096
	dbscChallengeKindRegistration = "registration"
	dbscBoundSessionCookieMaxAge  = 600
)

type dbscChallengePayload struct {
	Version int    `json:"v"`
	Kind    string `json:"kind"`
	SID     string `json:"sid"`
	IAT     int64  `json:"iat"`
	EXP     int64  `json:"exp"`
	Nonce   string `json:"nonce"`
}

type dbscRegistrationProofClaims struct {
	JTI string           `json:"jti"`
	JWK *jose.JSONWebKey `json:"jwk"`
	Sub string           `json:"sub,omitempty"`
	Aud []string         `json:"aud,omitempty"`
	IAT *jwt.NumericDate `json:"iat,omitempty"`
	EXP *jwt.NumericDate `json:"exp,omitempty"`
	NBF *jwt.NumericDate `json:"nbf,omitempty"`
}

type dbscProofValidationResult struct {
	PublicKey        jose.JSONWebKey
	ChallengePayload *dbscChallengePayload
}

type dbscSessionInstructionResponse struct {
	SessionIdentifier        string                       `json:"session_identifier"`
	RefreshURL               string                       `json:"refresh_url"`
	Scope                    dbscSessionInstructionScope  `json:"scope"`
	Credentials              []dbscSessionInstructionCred `json:"credentials"`
	AllowedRefreshInitiators []string                     `json:"allowed_refresh_initiators,omitempty"`
}

type dbscSessionInstructionScope struct {
	Origin      string `json:"origin"`
	IncludeSite bool   `json:"include_site"`
}

type dbscSessionInstructionCred struct {
	Type       string `json:"type"`
	Name       string `json:"name"`
	Attributes string `json:"attributes"`
}

func buildSecureSessionRegistrationHeader(challenge string) string {
	return fmt.Sprintf(`(%s);path=%q;challenge=%q`, dbscRegistrationAlgorithm, DBSCRegistrationPath, challenge)
}

func createDBSCChallenge(now time.Time, bearerToken, sessionID, kind string, ttl time.Duration) (string, error) {
	if bearerToken == "" {
		return "", trace.BadParameter("missing bearer token")
	}
	if sessionID == "" {
		return "", trace.BadParameter("missing app session id")
	}
	if kind != dbscChallengeKindRegistration {
		return "", trace.BadParameter("invalid challenge kind %q", kind)
	}
	if ttl <= 0 {
		return "", trace.BadParameter("invalid challenge ttl %v", ttl)
	}

	nonce, err := utils.CryptoRandomHex(defaults.TokenLenBytes)
	if err != nil {
		return "", trace.Wrap(err)
	}

	payload := dbscChallengePayload{
		Version: dbscChallengeVersion,
		Kind:    kind,
		SID:     sessionID,
		IAT:     now.Unix(),
		EXP:     now.Add(ttl).Unix(),
		Nonce:   nonce,
	}
	payloadRaw, err := json.Marshal(payload)
	if err != nil {
		return "", trace.Wrap(err)
	}

	sigRaw := signDBSCChallengePayload(payloadRaw, bearerToken)
	return fmt.Sprintf("%s.%s",
		base64.RawURLEncoding.EncodeToString(payloadRaw),
		base64.RawURLEncoding.EncodeToString(sigRaw),
	), nil
}

func validateDBSCChallenge(challenge string, now time.Time, bearerToken, expectedKind, expectedSessionID string) (*dbscChallengePayload, error) {
	if len(challenge) == 0 || len(challenge) > dbscChallengeMaxLen {
		return nil, trace.BadParameter("malformed dbsc challenge")
	}

	payloadEnc, sigEnc, ok := strings.Cut(challenge, ".")
	if !ok || payloadEnc == "" || sigEnc == "" {
		return nil, trace.BadParameter("malformed dbsc challenge")
	}

	payloadRaw, err := base64.RawURLEncoding.DecodeString(payloadEnc)
	if err != nil {
		return nil, trace.BadParameter("malformed dbsc challenge")
	}
	sigRaw, err := base64.RawURLEncoding.DecodeString(sigEnc)
	if err != nil {
		return nil, trace.BadParameter("malformed dbsc challenge")
	}

	wantSig := signDBSCChallengePayload(payloadRaw, bearerToken)
	if subtle.ConstantTimeCompare(sigRaw, wantSig) != 1 {
		return nil, trace.AccessDenied("invalid dbsc challenge")
	}

	var payload dbscChallengePayload
	if err := json.Unmarshal(payloadRaw, &payload); err != nil {
		return nil, trace.BadParameter("malformed dbsc challenge")
	}
	if payload.Version != dbscChallengeVersion || payload.Nonce == "" || payload.Kind == "" || payload.SID == "" || payload.IAT <= 0 || payload.EXP <= 0 {
		return nil, trace.AccessDenied("invalid dbsc challenge")
	}
	if payload.EXP <= payload.IAT {
		return nil, trace.AccessDenied("invalid dbsc challenge")
	}
	if now.Unix() < payload.IAT || now.Unix() > payload.EXP {
		return nil, trace.AccessDenied("invalid dbsc challenge")
	}
	if expectedKind != "" && payload.Kind != expectedKind {
		return nil, trace.AccessDenied("invalid dbsc challenge")
	}
	if expectedSessionID != "" && payload.SID != expectedSessionID {
		return nil, trace.AccessDenied("invalid dbsc challenge")
	}

	return &payload, nil
}

func signDBSCChallengePayload(payload []byte, bearerToken string) []byte {
	mac := hmac.New(sha256.New, deriveDBSCChallengeKey(bearerToken))
	mac.Write(payload)
	return mac.Sum(nil)
}

func deriveDBSCChallengeKey(bearerToken string) []byte {
	mac := hmac.New(sha256.New, []byte(dbscChallengeContextLabel))
	mac.Write([]byte(bearerToken))
	return mac.Sum(nil)
}

func parseSecureSessionResponseHeader(headerValue string) (string, error) {
	value := strings.TrimSpace(headerValue)
	if value == "" {
		return "", trace.AccessDenied("missing secure session proof")
	}
	if strings.HasPrefix(value, "\"") {
		unquoted, err := strconv.Unquote(value)
		if err != nil {
			return "", trace.BadParameter("malformed secure session proof")
		}
		value = unquoted
	}
	if value == "" {
		return "", trace.BadParameter("malformed secure session proof")
	}
	return value, nil
}

func validateDBSCRegistrationProof(rawProof string, now time.Time, registrationAudience, bearerToken, appSessionID string) (*dbscProofValidationResult, error) {
	token, err := jwt.ParseSigned(rawProof, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		return nil, trace.AccessDenied("invalid dbsc registration proof")
	}
	if len(token.Headers) == 0 {
		return nil, trace.AccessDenied("invalid dbsc registration proof")
	}
	header := token.Headers[0]
	if err := validateDBSCProofHeader(header, dbscRegistrationAlgorithm); err != nil {
		return nil, trace.AccessDenied("invalid dbsc registration proof")
	}

	var unverified dbscRegistrationProofClaims
	if err := token.UnsafeClaimsWithoutVerification(&unverified); err != nil {
		return nil, trace.AccessDenied("invalid dbsc registration proof")
	}
	if unverified.JTI == "" || unverified.JWK == nil || unverified.JWK.Key == nil || !unverified.JWK.IsPublic() {
		return nil, trace.AccessDenied("invalid dbsc registration proof")
	}
	if !containsAudience(unverified.Aud, registrationAudience) {
		return nil, trace.AccessDenied("invalid dbsc registration proof")
	}
	challengePayload, err := validateDBSCChallenge(unverified.JTI, now, bearerToken, dbscChallengeKindRegistration, appSessionID)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	var verified dbscRegistrationProofClaims
	if err := token.Claims(unverified.JWK.Key, &verified); err != nil {
		return nil, trace.AccessDenied("invalid dbsc registration proof")
	}
	if verified.JTI != unverified.JTI || verified.JWK == nil || verified.JWK.Key == nil {
		return nil, trace.AccessDenied("invalid dbsc registration proof")
	}

	return &dbscProofValidationResult{
		PublicKey:        *unverified.JWK,
		ChallengePayload: challengePayload,
	}, nil
}

func containsAudience(audiences []string, target string) bool {
	for _, aud := range audiences {
		if aud == target {
			return true
		}
	}
	return false
}

func marshalDBSCRegistrationJWK(publicJWK jose.JSONWebKey) (string, error) {
	if publicJWK.Key == nil || !publicJWK.IsPublic() {
		return "", trace.BadParameter("invalid dbsc public key")
	}
	raw, err := json.Marshal(publicJWK)
	if err != nil {
		return "", trace.Wrap(err)
	}
	return string(raw), nil
}

func validateDBSCProofHeader(header jose.Header, allowedAlgorithm string) error {
	typ, ok := header.ExtraHeaders[jose.HeaderKey(jose.HeaderType)].(string)
	if !ok || typ != dbscProofJWTType {
		return trace.AccessDenied("invalid dbsc proof header")
	}
	if allowedAlgorithm != "" && header.Algorithm != allowedAlgorithm {
		return trace.AccessDenied("invalid dbsc proof header")
	}
	return nil
}

func buildDBSCRegistrationResponse(r *http.Request, sessionIdentifier string) dbscSessionInstructionResponse {
	origin := "https://" + r.Host

	return dbscSessionInstructionResponse{
		SessionIdentifier: sessionIdentifier,
		RefreshURL:        DBSCRefreshPath,
		Scope: dbscSessionInstructionScope{
			Origin:      origin,
			IncludeSite: false,
		},
		Credentials: []dbscSessionInstructionCred{{
			Type:       "cookie",
			Name:       CookieName,
			Attributes: "Path=/; Secure; HttpOnly; SameSite=None",
		}},
		AllowedRefreshInitiators: []string{origin},
	}
}

func newAppSessionCookie(sessionID string, dbscBound bool) *http.Cookie {
	cookie := &http.Cookie{
		Name:     CookieName,
		Value:    sessionID,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteNoneMode,
	}
	if dbscBound {
		cookie.MaxAge = dbscBoundSessionCookieMaxAge
	}
	return cookie
}

func newSubjectSessionCookie(subjectToken string) *http.Cookie {
	return &http.Cookie{
		Name:     SubjectCookieName,
		Value:    subjectToken,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteNoneMode,
	}
}

func reissueDBSCBoundAppSessionCookie(w http.ResponseWriter, sessionID string) {
	http.SetCookie(w, newAppSessionCookie(sessionID, true))
}
