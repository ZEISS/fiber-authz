package authz

var _ AuthzChecker = (*noop)(nil)

type noop struct {
	Unimplemented
}

// NewNoop returns a new Noop authz checker
func NewNoop() *noop {
	return &noop{}
}
