package authz

// Noop is an authz checker that does nothing.
type Noop struct {
	Unimplemented
}

// NewNoop returns a new Noop authz checker.
func NewNoop() *Noop {
	return &Noop{}
}
