package core

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"os"
	"time"
)

const defaultTimeout = 30 * time.Second

// HTTPClient is a shared HTTP client with a reasonable timeout for platform use.
var HTTPClient = NewHTTPClientWithCerts(defaultTimeout)

// NewHTTPClientWithCerts creates an HTTP client configured with:
//   - CC_CONNECT_CA_CERT: path to a PEM-encoded CA certificate to append to the trust store
//   - CC_CONNECT_INSECURE_TLS: if set to "1"/"true", skip certificate verification (NOT recommended)
func NewHTTPClientWithCerts(timeout time.Duration) *http.Client {
	tlsConfig := &tls.Config{}

	caCertPath := os.Getenv("CC_CONNECT_CA_CERT")
	if caCertPath != "" {
		certPool, err := x509.SystemCertPool()
		if err != nil {
			certPool = x509.NewCertPool()
		}
		pem, err := os.ReadFile(caCertPath)
		if err == nil && certPool.AppendCertsFromPEM(pem) {
			tlsConfig.RootCAs = certPool
		}
	}

	if insecure, _ := isTruthy(os.Getenv("CC_CONNECT_INSECURE_TLS")); insecure {
		tlsConfig.InsecureSkipVerify = true
	}

	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}
}

func isTruthy(s string) (bool, error) {
	switch s {
	case "1", "true", "yes", "on":
		return true, nil
	case "0", "false", "no", "off", "":
		return false, nil
	default:
		return false, nil
	}
}
