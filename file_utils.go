package rolesanywherev4

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
)

func LoadSigningCert(path string) (*x509.Certificate, error) {
	signingCertificatePEM, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	b, _ := pem.Decode(signingCertificatePEM)
	return x509.ParseCertificate(b.Bytes)
}

func LoadSigningKey(path string) (*rsa.PrivateKey, error) {
	signingKey, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	p, _ := pem.Decode(signingKey)
	return x509.ParsePKCS1PrivateKey(p.Bytes)
}

func LoadCertsKeys(certPath, keyPath string) (*x509.Certificate, *rsa.PrivateKey, error) {
	cert, err := LoadSigningCert(certPath)
	if err != nil {
		return nil, nil, err
	}
	key, err := LoadSigningKey(keyPath)
	if err != nil {
		return nil, nil, err
	}
	return cert, key, nil
}
