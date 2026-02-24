package security_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/samandr77/microservices/payment/pkg/security"
)

//nolint:lll
func TestParsePublicKey(t *testing.T) {
	t.Parallel()

	publicKey := []byte(`-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAiBnToYsBxkwlUZtvCL55IJHM7uvLmA5ynDl9stsXrEw4Q7qdze87znK2cywOwnf6UD5BFtwtkkfep1kQajtkz2A4iKM3XhADPQ9UFIYu7LzCRBHq5O93Q+Ula4xHcQLYJUw6MvaxXtTmlYg5UDuAxv8tonQApZ//3GnKVMH0yvZ/5+MIbCztkTLLCIiSTtRg3ZeLg1vyXatlwCDFSDMtoelwoyse6hLZ13Js/o2vnYG87Ep3+lR5K0tuYzDRJeSv3PgP7vrn6AE2WNVd0C4F6OEqdUEm4SAvsoCH1LQV2p4SIqS23eu8k8UtmvjTX118oNa484WIVgOqyS3UmXNvYwIDAQAB
-----END PUBLIC KEY-----
`)

	_, err := security.ParsePublicKey(publicKey)
	require.NoError(t, err)
}

func TestParsePublicKeyFromFile(t *testing.T) {
	t.Parallel()

	_, err := security.ParsePublicKeyFromFile("testdata/public.pub")
	require.NoError(t, err)
}
