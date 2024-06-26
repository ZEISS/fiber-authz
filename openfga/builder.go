package openfga

import (
	"context"

	"github.com/openfga/go-sdk/client"
)

// DatastoreError is an error that occurred while executing a operation.
type DatastoreError struct {
	// Details are details to the operation
	Details string
	// Err is the error that occurred.
	Err error
}

// Error implements the error interface.
func (e *DatastoreError) Error() string { return e.Details + ": " + e.Err.Error() }

// Unwrap implements the errors.Wrapper interface.
func (e *DatastoreError) Unwrap() error { return e.Err }

// NewDatastoreError returns a new QueryError.
func NewDatastoreError(details string, err error) *DatastoreError {
	return &DatastoreError{
		Details: details,
		Err:     err,
	}
}

// Datastore provides methods for transactional operations.
type Datastore[R, W any] interface {
	// Read starts a read only transaction.
	Read(context.Context, func(context.Context, R) error) error
	// ReadWriteTx starts a read write transaction.
	ReadWrite(context.Context, func(context.Context, W) error) error
}

type datastoreImpl[R, W any] struct {
	r      ReadFactory[R]
	rw     ReadWriteFactory[W]
	client client.SdkClient
}

// ReadFactory is a function that creates a new instance of Datastore.
type ReadFactory[R any] func(client.SdkClient) (R, error)

// ReadWriteFactory is a function that creates a new instance of Datastore.
type ReadWriteFactory[W any] func(client.SdkClient) (W, error)

// NewDatastore returns a new instance of db.
func NewDatastore[R, W any](client client.SdkClient, r ReadFactory[R], rw ReadWriteFactory[W]) (Datastore[R, W], error) {
	return &datastoreImpl[R, W]{
		client: client,
	}, nil
}

// ReadWriteTx starts a read only transaction.
func (d *datastoreImpl[R, W]) ReadWrite(ctx context.Context, fn func(context.Context, W) error) error {
	tx, err := d.rw(d.client)
	if err != nil {
		return NewDatastoreError("read/write datastore", err)
	}

	err = fn(ctx, tx)
	if err != nil {
		return NewDatastoreError("read/write datastore", err)
	}

	return nil
}

// ReadTx starts a read only transaction.
func (d *datastoreImpl[R, W]) Read(ctx context.Context, fn func(context.Context, R) error) error {
	tx, err := d.r(d.client)
	if err != nil {
		return NewDatastoreError("read datastore", err)
	}

	err = fn(ctx, tx)
	if err != nil {
		return NewDatastoreError("read datastore", err)
	}

	return nil
}
