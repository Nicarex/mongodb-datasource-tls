package plugin

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
)

// CreateTLSConfig creates a tls.Config from PEM strings for client cert, client key, and CA cert
func CreateTLSConfig(clientCertPEM, caCertPEM, clientKeyPEM string) (*tls.Config, error) {
	caCertPool := x509.NewCertPool()
	if ok := caCertPool.AppendCertsFromPEM([]byte(caCertPEM)); !ok {
		return nil, fmt.Errorf("failed to parse CA certificate")
	}

	tlsConfig := &tls.Config{
		RootCAs: caCertPool,
	}
	// If both client cert and key are provided, use them
	if clientCertPEM != "" && clientKeyPEM != "" {
		cert, err := tls.X509KeyPair([]byte(clientCertPEM), []byte(clientKeyPEM))
		if err != nil {
			return nil, fmt.Errorf("failed to parse client certificate/key: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}
	return tlsConfig, nil
}
