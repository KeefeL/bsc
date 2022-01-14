package core

import "fmt"

type VerifyMode uint32

const (
	LocalVerify VerifyMode = iota //
	FullVerify
	LightVerify
	InsecureVerify
)

func (mode VerifyMode) IsValid() bool {
	return mode >= LocalVerify && mode <= InsecureVerify
}

func (mode VerifyMode) String() string {
	switch mode {
	case LocalVerify:
		return "local"
	case FullVerify:
		return "full"
	case LightVerify:
		return "light"
	case InsecureVerify:
		return "insecure"
	default:
		return "unknown"
	}
}

func (mode VerifyMode) MarshalText() ([]byte, error) {
	switch mode {
	case LocalVerify:
		return []byte("local"), nil
	case FullVerify:
		return []byte("full"), nil
	case LightVerify:
		return []byte("light"), nil
	case InsecureVerify:
		return []byte("insecure"), nil
	default:
		return nil, fmt.Errorf("unknown verify mode %d", mode)
	}
}

func (mode *VerifyMode) UnmarshalText(text []byte) error {
	switch string(text) {
	case "local":
		*mode = LocalVerify
	case "full":
		*mode = FullVerify
	case "light":
		*mode = LightVerify
	case "insecure":
		*mode = InsecureVerify
	default:
		return fmt.Errorf(`unknown sync mode %q, want "full", "light" or "insecure"`, text)
	}
	return nil
}

func (mode *VerifyMode) NeedRemoteVerify() bool {
	if *mode == FullVerify || *mode == LightVerify {
		return true
	}
	return false
}
