package sigv4

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
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

func SignedRequest(region, profileArn, roleArn, trustAnchorArn, signingCertPath, signingKeyPath string) (*http.Request, error) {
	t := Now().UTC()
	signingCert, err := loadSigningCert(signingCertPath)
	if err != nil {
		return nil, err
	}
	signingKey, err := loadSigningKey(signingKeyPath)
	if err != nil {
		return nil, err
	}
	req, err := createRequest(t, region, profileArn, roleArn, trustAnchorArn, signingCert)
	if err != nil {
		return nil, err
	}
	cr := CreateCanonicalRequest(*req)
	crHashed := HashedCanonicalRequest(cr)
	signedHeaders := strings.Join(SignedHeaders(*req), ";")
	credScope := fmt.Sprintf("%s/%s/rolesanywhere/aws4_request", t.Format("20060102"), region)

	credential := fmt.Sprintf("%s/%s", signingCert.SerialNumber, credScope)
	stringToSign := CreateStringToSign(t, credScope, crHashed)
	signature, err := GetSignature(*req, stringToSign, signingKey)
	if err != nil {
		return nil, err
	}

	addAuthHeader(req, "AWS4-X509-RSA-SHA256", credential, signedHeaders, signature)
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

func loadSigningCert(path string) (*x509.Certificate, error) {
	signingCertificatePEM, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	b, _ := pem.Decode(signingCertificatePEM)
	return x509.ParseCertificate(b.Bytes)
}

func loadSigningKey(path string) (*rsa.PrivateKey, error) {
	signingKey, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	p, _ := pem.Decode(signingKey)
	return x509.ParsePKCS1PrivateKey(p.Bytes)
}

func addAuthHeader(req *http.Request, algorithm, credential, signedHeaders, signature string) {
	authHeader := fmt.Sprintf("%s Credential=%s, SignedHeaders=%s, Signature=%s", algorithm, credential, signedHeaders, signature)
	req.Header.Set("Authorization", authHeader)
	req.Header.Add("content-type", "application/json")
}

func GetSignature(req http.Request, stringToSign string, signingKey *rsa.PrivateKey) (string, error) {
	hash := sha256.New()
	hash.Reset()
	hash.Write([]byte(stringToSign))
	digest := hash.Sum(nil)

	signed, err := signingKey.Sign(rand.Reader, digest, crypto.SHA256)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(signed), nil
}

func HashedCanonicalRequest(cr string) string {
	return hex.EncodeToString(MakeHash(sha256.New(), []byte(cr)))
}

func CreateCanonicalRequest(req http.Request) string {
	cHeaders := canonicalHeaders(req)
	hash, err := hashedPayload(req)
	if err != nil {
		panic(err)
	}
	uri := getURIPath(req.URL)
	query := query(req)

	return fmt.Sprintf("%s\n%s\n%s\n%s%s", req.Method, uri, query, cHeaders, hash)
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
	// Sort Each Query Key's Values
	for key := range query {
		sort.Strings(query[key])
	}
	var rawQuery strings.Builder
	rawQuery.WriteString(strings.Replace(query.Encode(), "+", "%20", -1))
	req.URL.RawQuery = rawQuery.String()
	return rawQuery.String()
}

func MakeHash(hash hash.Hash, b []byte) []byte {
	hash.Reset()
	hash.Write(b)
	return hash.Sum(nil)
}
