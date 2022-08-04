package main

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/mr-joshcrane/sigv4"
	"golang.org/x/crypto/ssh"
)

func main() {
	t := time.Now()
	got := Mine(t)
	want := Aidens(t)

	fmt.Println(cmp.Diff(want, got))
}
func Aidens(t time.Time) string {

	q := url.Values{}
	q.Set("profileArn", "arn:aws:rolesanywhere:ap-southeast-2:038021827431:profile/9419ce03-14c5-41e5-b0bc-62e717c53092")
	q.Set("roleArn", "arn:aws:iam::038021827431:role/TestRole")
	q.Set("trustAnchorArn", "arn:aws:rolesanywhere:ap-southeast-2:038021827431:trust-anchor/8f916267-7377-4d5d-a6f6-0b03f3feed3c")
	u := fmt.Sprintf("https://rolesanywhere.ap-southeast-2.amazonaws.com/sessions?%s", q.Encode())
	// inputPayload, _ := json.Marshal(map[string]any{"durationSeconds": 900})
	req, err := http.NewRequest(http.MethodPost, u, http.NoBody)
	if err != nil {
		panic(err)
	}

	certPEM, err := ioutil.ReadFile("./certs/inter.pem")
	if err != nil {
		panic(err)
	}
	cert, _ := pem.Decode(certPEM)
	c, err := x509.ParseCertificate(cert.Bytes)
	if err != nil {
		panic(err)
	}

	privateKey, err := ioutil.ReadFile("./certs/inter_key.pem")
	if err != nil {
		panic(err)
	}
	p, _ := pem.Decode(privateKey)

	parsedKey, err := x509.ParsePKCS1PrivateKey(p.Bytes)

	signer, err := ssh.NewSignerFromKey(parsedKey)
	if err != nil {
		panic(err)
	}
	sshsign := sigv4.SSHSigner{AlgorithmSigner: signer.(ssh.AlgorithmSigner)}

	payloadHashHex := hex.EncodeToString(sigv4.MakeHash(sha256.New(), []byte{}))

	err = sigv4.SignHTTP(
		c,
		&sshsign,
		req,
		payloadHashHex,
		"rolesanywhere",
		"ap-southeast-2",
		t,
	)
	if err != nil {
		panic(err)
	}

	client := &http.Client{}

	// fmt.Println(req)
	resp, err := client.Do(req)
	fmt.Println(resp, err)
	bdy, _ := io.ReadAll(resp.Body)
	fmt.Println(string(bdy))
	return req.Header.Get("Authorization")
}

func Mine(t time.Time) string {
	q := url.Values{}
	q.Set("profileArn", "arn:aws:rolesanywhere:ap-southeast-2:038021827431:profile/9419ce03-14c5-41e5-b0bc-62e717c53092")
	q.Set("roleArn", "arn:aws:iam::038021827431:role/TestRole")
	q.Set("trustAnchorArn", "arn:aws:rolesanywhere:ap-southeast-2:038021827431:trust-anchor/8f916267-7377-4d5d-a6f6-0b03f3feed3c")
	u := fmt.Sprintf("https://rolesanywhere.ap-southeast-2.amazonaws.com/sessions?%s", q.Encode())
	t = t.UTC()
	req, err := http.NewRequest(http.MethodPost, u, http.NoBody)
	if err != nil {
		panic(err)
	}

	req.Header.Add("X-Amz-Date", t.Format("20060102T150405Z"))
	req.Header.Add("host", "rolesanywhere.ap-southeast-2.amazonaws.com")

	certPEM, err := ioutil.ReadFile("./certs/inter.pem")
	if err != nil {
		panic(err)
	}
	cert, _ := pem.Decode(certPEM)

	req.Header.Add("X-Amz-X509", base64.StdEncoding.EncodeToString(cert.Bytes))

	keyPEM, err := ioutil.ReadFile("./certs/inter_key.pem")
	if err != nil {
		panic(err)
	}
	signedHeaders := strings.Join(sigv4.SignedHeaders(*req), ";")
	cr := sigv4.CreateCanonicalRequest(*req)
	fmt.Println(cr)

	// p, _ := pem.Decode(keyPEM)

	// parsedKey, err := x509.ParsePKCS1PrivateKey(p.Bytes)
	// signer, err := ssh.NewSignerFromKey(parsedKey)
	// if err != nil {
	// 	panic(err)
	// }
	// sshsign := sigv4.SSHSigner{AlgorithmSigner: signer.(ssh.AlgorithmSigner)}

	certSerial := "2"

	credScope := t.Format("20060102") + "/ap-southeast-2/rolesanywhere/aws4_request"
	hash := sigv4.HashedCanonicalRequest(cr)
	stringToSign := sigv4.CreateStringToSign(*req, credScope, hash)

	// fmt.Println(stringToSign)

	credential := fmt.Sprintf("%s/%s", certSerial, credScope)
	signature := sigv4.GetSignature(*req, stringToSign, keyPEM)
	auth := sigv4.CreateAuthorization("AWS4-X509-RSA-SHA256", credential, signedHeaders, signature)
	req.Header.Set("Authorization", auth)

	client := &http.Client{}
	req.Header.Add("content-type", "application/json")
	// fmt.Println(req)
	resp, err := client.Do(req)
	fmt.Println(resp, err)
	bdy, _ := io.ReadAll(resp.Body)
	fmt.Println(string(bdy))
	return auth
}
