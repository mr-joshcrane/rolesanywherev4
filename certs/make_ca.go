package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io/fs"
	"io/ioutil"
	"math/big"
	"os"
	"time"
)

func main() {
	key, err := createCA()
	if err != nil {
		panic(err)
	}
	err = createIntermediate(key)
	if err != nil {
		panic(err)
	}

	rootCA, err := ioutil.ReadFile("./certs/ca.pem")
	if err != nil {
		panic(err)
	}
	block, _ := pem.Decode(rootCA)
	rCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		panic(err)
	}
	interCert, err := ioutil.ReadFile("./certs/inter.pem")
	if err != nil {
		panic(err)
	}
	block, _ = pem.Decode(interCert)
	iCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		panic(err)
	}
	rootPool := x509.NewCertPool()
	rootPool.AddCert(rCert)

	c, err := iCert.Verify(x509.VerifyOptions{
		Roots: rootPool,
	})
	if err != nil {
		panic(err)
	}
	fmt.Println(c)

}

func createCA() (*rsa.PrivateKey, error) {
	name := pkix.Name{
		SerialNumber: fmt.Sprintf("%d", 1),
		CommonName:   "Tukan",
	}
	serialNumber := &big.Int{}
	serialNumber, ok := serialNumber.SetString("1", 10)
	if !ok {
		return nil, fmt.Errorf("not a base10 serial number: %s", "1")
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	keyBytes := x509.MarshalPKCS1PrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyBytes})
	err = ioutil.WriteFile("./certs/ca_key.pem", keyPEM, 0700)
	if err != nil {
		return nil, fmt.Errorf("writing certificate to filesystem: %w", err)
	}
	fileInfo, err := os.Stat("./certs/ca_key.pem")
	if err != nil {
		return nil, fmt.Errorf("couldn't read file: %w", err)
	}
	// Check for prepopulation attack
	if fileInfo.Mode() != fs.FileMode(0700) {
		return nil, fmt.Errorf("file didn't have expected permissions %w", err)
	}


	ca := &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               name,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 365 * 24),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, key.Public(), key)
	if err != nil {
		panic(err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caBytes})
	err = ioutil.WriteFile("./certs/ca.pem", certPEM, 0700)
	if err != nil {
		return nil, fmt.Errorf("writing certificate to filesystem: %w", err)
	}
	fileInfo, err = os.Stat("./certs/ca.pem")
	if err != nil {
		return nil, fmt.Errorf("couldn't read file: %w", err)
	}
	// Check for prepopulation attack
	if fileInfo.Mode() != fs.FileMode(0700) {
		return nil, fmt.Errorf("file didn't have expected permissions %w", err)
	}

	return key, nil
}

func createIntermediate(parentKey *rsa.PrivateKey) error {
	caPEM, err := ioutil.ReadFile("./certs/ca.pem")
	if err != nil {
		panic(err)
	}
	block, _ := pem.Decode(caPEM)
	ca, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}
	name := pkix.Name{
		SerialNumber: fmt.Sprintf("%d", 2),
		CommonName:   "Tukan",
	}
	serialNumber := &big.Int{}
	serialNumber, ok := serialNumber.SetString("2", 10)
	if !ok {
		return fmt.Errorf("not a base10 serial number: %s", "2")
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	keyBytes:= x509.MarshalPKCS1PrivateKey(key)

	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyBytes})
	err = ioutil.WriteFile("./certs/inter_key.pem", keyPEM, 0700)
	if err != nil {
		return fmt.Errorf("writing certificate to filesystem: %w", err)
	}
	fileInfo, err := os.Stat("./certs/inter_key.pem")
	if err != nil {
		return fmt.Errorf("couldn't read file: %w", err)
	}
	// Check for prepopulation attack
	if fileInfo.Mode() != fs.FileMode(0700) {
		return fmt.Errorf("file didn't have expected permissions %w", err)
	}


	inter := &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               name,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 365 * 24),
		ExtKeyUsage:   		   []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA: false,
		SignatureAlgorithm: x509.SHA256WithRSA,
	}

	interBytes, err := x509.CreateCertificate(rand.Reader, inter, ca, key.Public(), parentKey)
	if err != nil {
		panic(err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: interBytes})
	err = ioutil.WriteFile("./certs/inter.pem", certPEM, 0700)
	if err != nil {
		return fmt.Errorf("writing certificate to filesystem: %w", err)
	}
	fileInfo, err = os.Stat("./certs/inter.pem")
	if err != nil {
		return fmt.Errorf("couldn't read file: %w", err)
	}
	// Check for prepopulation attack
	if fileInfo.Mode() != fs.FileMode(0700) {
		return fmt.Errorf("file didn't have expected permissions %w", err)
	}
	return nil
}