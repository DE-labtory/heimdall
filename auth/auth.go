package auth

import "heimdall"

type Auth interface {

	Sign(key heimdall.Key, data []byte, opts SignerOpts) ([]byte, error)

	Verify(key heimdall.Key, signature, digest []byte, opts SignerOpts) (bool, error)

}