package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
)

// generateKeyAndCSR creates a local keypair and a PKCS#10 CSR. The private
// key never leaves this process/the local config file -- only the CSR is
// sent to the platform, which signs it with the BAS root CA (bas_ca.py) and
// returns a client certificate bound to this specific agent_id.
func generateKeyAndCSR() (keyPEM string, csrPEM string, err error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", err
	}
	template := x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "bas-agent-bootstrap"},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &template, key)
	if err != nil {
		return "", "", err
	}
	keyDER := x509.MarshalPKCS1PrivateKey(key)
	keyBlock := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyDER})
	csrBlock := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	return string(keyBlock), string(csrBlock), nil
}
