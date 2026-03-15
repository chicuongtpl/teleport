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

package client

import (
	"context"
	"io"

	"github.com/gravitational/trace"

	"github.com/gravitational/teleport/api/client/proto"
	"github.com/gravitational/teleport/api/mfa"
	libmfa "github.com/gravitational/teleport/lib/client/mfa"
	"github.com/gravitational/teleport/lib/client/sso"
)

// NewMFACeremony returns a new MFA ceremony configured for this client.
func (tc *TeleportClient) NewMFACeremony() *mfa.Ceremony {
	c := &mfa.Ceremony{
		CreateAuthenticateChallenge: tc.createAuthenticateChallenge,
		PromptConstructor:           tc.NewMFAPrompt,
		SSOMFACeremonyConstructor:   tc.NewSSOMFACeremony,
		Ping:                        tc.Ping,
	}

	if tc.RegisterMFADeviceIfRequired {
		c.AddMFADevice = tc.addMFADevice
		c.CreateRegisterChallenge = tc.createRegisterChallenge
	}

	return c
}

// createAuthenticateChallenge creates and returns MFA challenges for a users registered MFA devices.
func (tc *TeleportClient) createAuthenticateChallenge(ctx context.Context, req *proto.CreateAuthenticateChallengeRequest) (*proto.MFAAuthenticateChallenge, error) {
	clusterClient, err := tc.ConnectToCluster(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	rootClient, err := clusterClient.ConnectToRootCluster(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return rootClient.CreateAuthenticateChallenge(ctx, req)
}

// createRegisterChallenge creates and returns an MFA registration challenge for a user.
func (tc *TeleportClient) createRegisterChallenge(ctx context.Context, req *proto.CreateRegisterChallengeRequest) (*proto.MFARegisterChallenge, error) {
	clusterClient, err := tc.ConnectToCluster(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	rootClient, err := clusterClient.ConnectToRootCluster(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return rootClient.CreateRegisterChallenge(ctx, req)
}

func (tc *TeleportClient) addMFADevice(ctx context.Context, resp *proto.MFARegisterResponse, config mfa.RegisterDeviceConfig) error {
	clusterClient, err := tc.ConnectToCluster(ctx)
	if err != nil {
		return trace.Wrap(err)
	}
	rootClient, err := clusterClient.ConnectToRootCluster(ctx)
	if err != nil {
		return trace.Wrap(err)
	}

	_, err = rootClient.AddMFADeviceSync(ctx, &proto.AddMFADeviceSyncRequest{
		NewDeviceName:  config.Name,
		NewMFAResponse: resp,
		DeviceUsage: func() proto.DeviceUsage {
			if config.AllowPasswordless {
				return proto.DeviceUsage_DEVICE_USAGE_PASSWORDLESS
			}
			return proto.DeviceUsage_DEVICE_USAGE_MFA
		}(),
	})
	return trace.Wrap(err)
}

// WebauthnLoginFunc is a function that performs WebAuthn login.
// Mimics the signature of [webauthncli.Login].
type WebauthnLoginFunc = libmfa.WebauthnLoginFunc

// WebauthnRegisterFunc is a function that performs WebAuthn registration.
// Mimics the signature of [wancli.Register].
type WebauthnRegisterFunc = libmfa.WebauthnRegisterFunc

// TouchIDRegisterFunc is a function that performs Touch ID registration.
type TouchIDRegisterFunc = libmfa.TouchIDRegisterFunc

// NewMFAPrompt creates a new MFA prompt from client settings.
func (tc *TeleportClient) NewMFAPrompt(opts ...mfa.PromptOpt) mfa.Prompt {
	cfg := tc.newPromptConfig(opts...)

	var prompt mfa.Prompt = libmfa.NewCLIPrompt(&libmfa.CLIPromptConfig{
		PromptConfig:        *cfg,
		Writer:              tc.Stderr,
		PreferOTP:           tc.PreferOTP,
		PreferSSO:           tc.PreferSSO,
		AllowStdinHijack:    tc.AllowStdinHijack,
		StdinFunc:           tc.StdinFunc,
		StdoutFunc:          func() io.Writer { return tc.Stdout },
		CeremonyConstructor: tc.NewMFACeremony,
	})

	if tc.MFAPromptConstructor != nil {
		prompt = tc.MFAPromptConstructor(cfg)
	}

	return prompt
}

func (tc *TeleportClient) newPromptConfig(opts ...mfa.PromptOpt) *libmfa.PromptConfig {
	cfg := libmfa.NewPromptConfig(tc.WebProxyAddr, opts...)
	cfg.AuthenticatorAttachment = tc.AuthenticatorAttachment
	if tc.WebauthnLogin != nil {
		cfg.WebauthnLoginFunc = tc.WebauthnLogin
		cfg.WebauthnSupported = true
	}
	if tc.WebauthnRegister != nil {
		cfg.WebauthnRegisterFunc = tc.WebauthnRegister
		cfg.WebauthnSupported = true
	}
	if tc.TouchIDRegister != nil {
		cfg.TouchIDRegisterFunc = tc.TouchIDRegister
	}

	return cfg
}

// NewSSOMFACeremony creates a new SSO MFA ceremony.
func (tc *TeleportClient) NewSSOMFACeremony(ctx context.Context) (mfa.SSOMFACeremony, error) {
	rdConfig, err := tc.ssoRedirectorConfig(ctx, "" /*connectorDisplayName*/)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	rd, err := sso.NewRedirector(rdConfig)
	if err != nil {
		return nil, trace.Wrap(err, "failed to create a redirector for SSO MFA")
	}

	if tc.SSOMFACeremonyConstructor != nil {
		return tc.SSOMFACeremonyConstructor(rd), nil
	}

	return sso.NewCLIMFACeremony(rd), nil
}

func (tc *TeleportClient) AddMFA(ctx context.Context, rdc mfa.RegisterDeviceConfig) (bool, error) {
	if rdc.Type == "" {
		// If we are prompting the user for the device type, then take a glimpse at
		// server-side settings and adjust the options accordingly.
		// This is undesirable to do during flag setup, but we can do it here.
		pingResp, err := tc.Ping(ctx)
		if err != nil {
			return false, trace.Wrap(err)
		}
		rdc.AuthSecondFactor = pingResp.Auth.SecondFactor
	}
	ceremony := &mfa.Ceremony{
		CreateAuthenticateChallenge: tc.createAuthenticateChallenge,
		PromptConstructor:           tc.NewMFAPrompt,
		SSOMFACeremonyConstructor:   tc.NewSSOMFACeremony,
		Ping:                        tc.Ping,
		AddMFADevice:                tc.addMFADevice,
		CreateRegisterChallenge:     tc.createRegisterChallenge,
	}
	added, err := ceremony.Register(ctx, rdc)
	return added, trace.Wrap(err)
}
