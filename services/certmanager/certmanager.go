package certmanager

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"time"

	"github.com/untangle/packetd/services/logger"
)

func Startup() {
	logger.Info("Starting up the certificate manager service\n")
}

func Shutdown() {
	logger.Info("Shutting down the certificate manager service\n")
}

func GetConfiguredCert() (path string, pemKey string) {
	return generateSelfSigned()
}

// generateSelfSigned will generate a self signed cert
// most of the logic taken from here: https://golang.org/src/crypto/tls/generate_cert.go
func generateSelfSigned() (path string, pemKey string) {
	var priv interface{}
	var err error
	var hostIps []net.IP
	var hostnames []string
	var certPath = "/tmp/cert.pem"
	var keyPath = "/tmp/key.pem"

	priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		logger.Warn("Failed to generate P256 private key: %s", err)
	}

	var validFrom time.Time
	var validTo time.Time

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		logger.Warn("failed to generate serial number: %s", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Acme Co"},
		},
		NotBefore:             validFrom,
		NotAfter:              validTo,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           hostIps,
		DNSNames:              hostnames,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, publicKey(priv), priv)
	if err != nil {
		logger.Warn("Failed to create certificate: %v", err)
	}

	certOut, err := os.Create(certPath)
	if err != nil {
		logger.Warn("Failed to open cert.pem for writing: %s", err)
	}
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		logger.Warn("failed to write data to cert.pem: %s", err)
	}
	if err := certOut.Close(); err != nil {
		logger.Warn("error closing cert.pem: %s", err)
	}

	keyOut, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		logger.Warn("failed to open key.pem for writing: %v", err)
		return
	}
	if err := pem.Encode(keyOut, pemBlockForKey(priv)); err != nil {
		logger.Warn("failed to write data to key.pem: %s", err)
	}
	if err := keyOut.Close(); err != nil {
		logger.Warn("error closing key.pem: %s", err)
	}

	return
}

func publicKey(priv interface{}) interface{} {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	default:
		return nil
	}
}

func pemBlockForKey(priv interface{}) *pem.Block {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}
	case *ecdsa.PrivateKey:
		b, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Unable to marshal ECDSA private key: %v", err)
			os.Exit(2)
		}
		return &pem.Block{Type: "EC PRIVATE KEY", Bytes: b}
	default:
		return nil
	}
}
