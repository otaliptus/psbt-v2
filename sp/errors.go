package sp

import "errors"

var (
	ErrNoSilentPaymentOutputs = errors.New("packet has no silent payment outputs")
	ErrMissingInputPublicKey  = errors.New("eligible input missing public key")
	ErrNoEligibleInputs       = errors.New("packet has no eligible silent payment inputs")
	ErrMissingOutputAmount    = errors.New("silent payment output missing amount")
)
