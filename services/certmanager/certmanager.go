package certmanager

import (
	"bytes"
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

	"github.com/untangle/golang-shared/services/logger"
	"github.com/untangle/golang-shared/services/settings"
)

// Startup is called when the packetd service starts
func Startup() {
	logger.Info("Starting up the certificate manager service\n")
}

// Shutdown is called when the packetd service stops
func Shutdown() {
	logger.Info("Shutting down the certificate manager service\n")
}

// GetConfiguredCert should retrieve configured certificates, or generate a self signed cert for mfw_admin
func GetConfiguredCert() (certPath string, keyPath string) {
	certPath, keyPath = generateSelfSigned()
	return
}

// generateSelfSigned will generate a self signed cert into the /tmp/ directory, the cert will be valid for 10 years
// most of the logic taken from here: https://golang.org/src/crypto/tls/generate_cert.go
func generateSelfSigned() (certPath string, keyPath string) {
	var ca *x509.Certificate
	var caPrivKey *ecdsa.PrivateKey
	var certKey *ecdsa.PrivateKey
	var certBytes []byte

	certPath = "/tmp/cert.pem"
	keyPath = "/tmp/cert.key"

	logger.Debug("Validating existing cert and path...\n")
	if !checkCertKeyValidity(certPath, keyPath) {
		logger.Debug("Create CA key info...\n")
		ca, caPrivKey = createCACert()

		logger.Debug("Create MFW Certificate info...\n")
		certBytes, certKey = createCert(ca, caPrivKey)

		logger.Debug("Save MFW cert info...\n")
		saveCertificates(certPath, certBytes, keyPath, certKey)
	}
	logger.Debug("Self signed cert and key generation complete.\n")
	return
}

// checkCertKeyValidity will validate the certpath and keypath files to determine if the input certificate and key is valid
func checkCertKeyValidity(certPath string, keyPath string) bool {
	if info, err := os.Stat(certPath); os.IsNotExist(err) || info.IsDir() {
		return false
	}

	if info, err := os.Stat(keyPath); os.IsNotExist(err) || info.IsDir() {
		return false
	}

	return true
}

// createCACert will generate a ca certificate and private key
func createCACert() (ca *x509.Certificate, caPrivKey *ecdsa.PrivateKey) {
	ca = &x509.Certificate{
		SerialNumber: big.NewInt(2019),
		Subject: pkix.Name{
			CommonName:         "www.untangle.com",
			OrganizationalUnit: []string{"Security"},
			Organization:       []string{"Untangle"},
			Locality:           []string{"Sunnyvale"},
			Province:           []string{"California"},
			Country:            []string{"US"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	caPrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		logger.Warn("Failed to generate P256 private key: %s", err)
	}

	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		logger.Warn("Failed to create P256 CA private key: %s", err)
	}

	caPEM := new(bytes.Buffer)
	pem.Encode(caPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	})

	caPrivKeyPEM := new(bytes.Buffer)
	caPrivBytes, err := x509.MarshalECPrivateKey(caPrivKey)
	if err != nil {
		logger.Warn("Failed to Marshal EC Private key for CA: %s", err)
	}

	pem.Encode(caPrivKeyPEM, &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: caPrivBytes,
	})

	return
}

// createCert will create a certificate (in bytes) and private key and sign using a given CA
func createCert(ca *x509.Certificate, caPrivKey *ecdsa.PrivateKey) (certBytes []byte, privateKey *ecdsa.PrivateKey) {
	var hostIps []net.IP
	var hostnames []string
	domainName := getSystemSetting("domainName")

	hostIps = append(hostIps, net.IPv4(127, 0, 0, 1))
	hostnames = append(hostnames, "localhost")
	hostnames = append(hostnames, getSystemSetting("hostName"))

	logger.Debug("Generating new private key...\n")
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		logger.Warn("Failed to generate P256 private key: %s", err)
	}

	logger.Debug("Generating new serial number for certificate...\n")
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		logger.Warn("failed to generate serial number: %s", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   string(domainName),
			Organization: []string{domainName},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           hostIps,
		DNSNames:              hostnames,
	}

	logger.Debug("Creating certificate...\n")
	certBytes, err = x509.CreateCertificate(rand.Reader, &template, ca, privateKey.Public(), caPrivKey)
	if err != nil {
		logger.Warn("Failed to create certificate: %v", err)
	}

	return
}

// saveCertificates will save the certificate bytes and certificate private keys into given certPath and keyPath files
func saveCertificates(certPath string, certBytes []byte, keyPath string, certKey *ecdsa.PrivateKey) {

	logger.Debug("Writing out %s...\n", certPath)
	certOut, err := os.Create(certPath)
	if err != nil {
		logger.Warn("Failed to open %s for writing: %s", certPath, err)
	}
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes}); err != nil {
		logger.Warn("failed to write data to %s: %s", certPath, err)
	}
	if err := certOut.Close(); err != nil {
		logger.Warn("error closing %s: %s", certPath, err)
	}

	logger.Debug("Writing out %s...\n", keyPath)
	keyOut, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		logger.Warn("failed to open %s for writing: %v", keyPath, err)
		return
	}
	if err := pem.Encode(keyOut, pemBlockForKey(certKey)); err != nil {
		logger.Warn("failed to write data to %s: %s", keyPath, err)
	}
	if err := keyOut.Close(); err != nil {
		logger.Warn("error closing %s: %s", keyPath, err)
	}
}

// pemBlockForKey will return the pem block begin/end statements for a given private key
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

// getSystemSetting will use a setting name as input to retrieve system settings
func getSystemSetting(settingName string) string {
	settingValue, err := settings.GetSettings([]string{"system", settingName})
	if err != nil {
		logger.Warn("Failed to read setting value for setting %s, error: %v\n", settingName, err.Error())
		return ""
	}

	return settingValue.(string)
}
