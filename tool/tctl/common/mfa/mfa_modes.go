package mfa

import (
	"fmt"

	wancli "github.com/gravitational/teleport/lib/auth/webauthncli"
)

const (
	// mfaModeAuto automatically chooses the best MFA device(s), without any
	// restrictions.
	MFAModeAuto = "auto"
	// MFAModeCrossPlatform utilizes only cross-platform devices, such as
	// pluggable hardware keys.
	// Implies Webauthn.
	MFAModeCrossPlatform = "cross-platform"
	// MFAModePlatform utilizes only platform devices, such as Touch ID.
	// Implies Webauthn.
	MFAModePlatform = "platform"
	// MFAModeSSO utilizes only SSO devices.
	MFAModeSSO = "sso"
	// MFAModeBrowser utilizes browser-based WebAuthn MFA.
	MFAModeBrowser = "browser"
)

type MFAModeOpts struct {
	AuthenticatorAttachment wancli.AuthenticatorAttachment
	PreferSSO               bool
	PreferBrowser           bool
}

func ParseMFAMode(mode string) (*MFAModeOpts, error) {
	opts := &MFAModeOpts{}
	switch mode {
	case "", MFAModeAuto:
	case MFAModeCrossPlatform:
		opts.AuthenticatorAttachment = wancli.AttachmentCrossPlatform
	case MFAModePlatform:
		opts.AuthenticatorAttachment = wancli.AttachmentPlatform
	case MFAModeSSO:
		opts.PreferSSO = true
	case MFAModeBrowser:
		opts.PreferBrowser = true
	default:
		return nil, fmt.Errorf("invalid MFA mode: %q", mode)
	}
	return opts, nil
}
