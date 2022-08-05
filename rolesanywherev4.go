package rolesanywherev4

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"hash"
	"io/ioutil"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

var Now = time.Now

func SignRequest(region, profileArn, roleArn, trustAnchorArn string, signingCert *x509.Certificate, signingKey *rsa.PrivateKey) (*http.Request, error) {
	t := Now().UTC()
	req, err := createRequest(t, region, profileArn, roleArn, trustAnchorArn, signingCert)
	if err != nil {
		return nil, err
	}
	_, crHashed, err := CreateCanonicalRequest(*req)
	if err != nil {
		return nil, err
	}

	credScope := fmt.Sprintf("%s/%s/rolesanywhere/aws4_request", t.Format("20060102"), region)
	credential := fmt.Sprintf("%s/%s", signingCert.SerialNumber, credScope)
	stringToSign := CreateStringToSign(t, credScope, crHashed)
	signature, err := GetSignature(*req, stringToSign, signingKey)
	if err != nil {
		return nil, err
	}

	addAuthHeader(req, "AWS4-X509-RSA-SHA256", credential, signature)
	return req, nil
}

func createRequest(t time.Time, region, profileArn, roleArn, trustAnchorArn string, signingCert *x509.Certificate) (*http.Request, error) {
	q := url.Values{}
	q.Set("profileArn", profileArn)
	q.Set("roleArn", roleArn)
	q.Set("trustAnchorArn", trustAnchorArn)
	url := fmt.Sprintf("https://rolesanywhere.%s.amazonaws.com/sessions?%s", region, q.Encode())
	req, err := http.NewRequest(http.MethodPost, url, http.NoBody)
	if err != nil {
		return nil, err
	}

	req.Header.Add("X-Amz-Date", t.UTC().Format("20060102T150405Z"))
	req.Header.Add("host", fmt.Sprintf("rolesanywhere.%s.amazonaws.com", region))
	req.Header.Add("X-Amz-X509", base64.StdEncoding.EncodeToString(signingCert.Raw))
	return req, nil
}

func addAuthHeader(req *http.Request, algorithm, credential, signature string) {
	signedHeaders := strings.Join(SignedHeaders(*req), ";")
	authHeader := fmt.Sprintf("%s Credential=%s, SignedHeaders=%s, Signature=%s", algorithm, credential, signedHeaders, signature)
	req.Header.Set("Authorization", authHeader)
	req.Header.Add("content-type", "application/json")
}

func GetSignature(req http.Request, stringToSign string, signingKey *rsa.PrivateKey) (string, error) {
	digest := makeHash(sha256.New(), []byte(stringToSign))

	signed, err := signingKey.Sign(rand.Reader, digest, crypto.SHA256)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(signed), nil
}

func CreateCanonicalRequest(req http.Request) (canonicalRequest, hashedCanonicalRequest string, err error) {
	cHeaders := canonicalHeaders(req)
	hash, err := hashedPayload(req)
	if err != nil {
		return "", "", err
	}
	uri := getURIPath(req.URL)
	query := query(req)
	canonicalRequest = fmt.Sprintf("%s\n%s\n%s\n%s%s", req.Method, uri, query, cHeaders, hash)
	hashedCanonicalRequest = hex.EncodeToString(makeHash(sha256.New(), []byte(canonicalRequest)))

	return canonicalRequest, hashedCanonicalRequest, nil
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
		cHeaders.WriteString(fmt.Sprintf("%s:%s\n", k, v))
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

func CreateStringToSign(t time.Time, credScope, hash string) string {
	return fmt.Sprintf("AWS4-X509-RSA-SHA256\n%s\n%s\n%s", t.Format("20060102T150405Z"), credScope, hash)
}

func getURIPath(u *url.URL) string {
	var uri string
	if len(u.Opaque) > 0 {
		uri = "/" + strings.Join(strings.Split(u.Opaque, "/")[3:], "/")
	} else {
		uri = u.EscapedPath()
	}
	if len(uri) == 0 {
		uri = "/"
	}
	return uri
}

func query(req http.Request) string {
	query := req.URL.Query()
	for key := range query {
		sort.Strings(query[key])
	}
	var rawQuery strings.Builder
	rawQuery.WriteString(strings.Replace(query.Encode(), "+", "%20", -1))
	req.URL.RawQuery = rawQuery.String()
	return rawQuery.String()
}

func makeHash(hash hash.Hash, b []byte) []byte {
	hash.Reset()
	hash.Write(b)
	return hash.Sum(nil)
}
