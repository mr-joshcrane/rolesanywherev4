package sigv4

import (
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/http"
	"sort"
	"strings"
)

func HashedCanonicalRequest(cr string) string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(cr)))
}

func CreateCanonicalRequest(req http.Request) string {
	cHeaders := canonicalHeaders(req)
	hash, err := hashedPayload(req)
	if err != nil {
		panic(err)
	}
	return fmt.Sprintf("%s\n/%s\n%s\n%s%s", req.Method, req.RequestURI, req.URL.RawQuery, cHeaders, hash)
}

func hashedPayload(req http.Request) (string, error) {
	body, err := ioutil.ReadAll(req.Body)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", sha256.Sum256(body)), nil
}

func canonicalHeaders(req http.Request) string {
	cHeaders := strings.Builder{}
	req.Header.Set("host", req.Host)
	header_keys := SignedHeaders(req)
	for _, k := range header_keys {
		v := req.Header.Get(k)
		_, err := cHeaders.WriteString(fmt.Sprintf("%s:%s\n", k, v))
		if err != nil {
			panic(err)
		}
	}
	cHeaders.WriteString("\n")
	cHeaders.WriteString(strings.Join(header_keys, ";"))
	cHeaders.WriteString("\n")
	return cHeaders.String()
}

func SignedHeaders(req http.Request) []string {
	var header_keys []string
	for k := range req.Header {
		header_keys = append(header_keys, strings.ToLower(k))
	}
	sort.Strings(header_keys)
	return header_keys
}

func CreateStringToSign(req http.Request, credScope string, hashedCR string) string {
	requestTimestamp := req.Header.Get("x-amz-date")
	return fmt.Sprintf("AWS4-X509-RSA-SHA256\n%s\n%s\n%s", requestTimestamp, credScope, hashedCR)
}

func GetSignature(req http.Request, stringToSign string, privateKey string) string {
	p, _ := pem.Decode([]byte(privateKey))
	parsedKey, err := x509.ParsePKCS1PrivateKey(p.Bytes)
	if err != nil {
		panic(err)
	}
	digest := sha256.Sum256([]byte(stringToSign))
	signed, err := parsedKey.Sign(rand.Reader, digest[:], crypto.SignerOpts.HashFunc(crypto.SHA256))
	if err != nil {
		panic(err)
	}
	
	return fmt.Sprintf("%x", signed)
}

func SignRequest(req *http.Request, auth string) {
	req.Header.Set("Authorization", auth)
}

func CreateAuthorization(algorithm string, credential string, signedHeaders string, signature string) string {
	return fmt.Sprintf("%s Credential=%s, SignedHeaders=%s, Signature=%s", algorithm, credential, signedHeaders, signature)
}

type RequestBody struct {
	DurationSeconds int
	ProfileArn      string
	RoleArn         string
	SessionName     string
	TrustAnchorArn  string
}
