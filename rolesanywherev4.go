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

type config struct {
	profileArn     string
	roleArn        string
	trustAnchorArn string
	region         string
	signingCert    *x509.Certificate
	signingKey     *rsa.PrivateKey

	// These fields are derived during signing
	canonicalRequest       string
	canonicalRequestHashed string
	credScope              string
	credential             string
	stringToSign           string
	signature              string
}

func NewRolesAnywhereConfig(profileArn, roleArn, trustAnchorArn, region string, signingCert *x509.Certificate, signingKey *rsa.PrivateKey) *config {
	return &config{
		profileArn:     profileArn,
		roleArn:        roleArn,
		trustAnchorArn: trustAnchorArn,
		region:         "ap-southeast-2",
		signingCert:    signingCert,
		signingKey:     signingKey,
	}
}

var Now = time.Now

func SignRequest(c *config) (*http.Request, error) {
	t := Now().UTC()
	req, err := createRequest(c, t)
	if err != nil {
		return nil, err
	}
	err = createCanonicalRequest(c, *req)
	if err != nil {
		return nil, err
	}

	c.credScope = fmt.Sprintf("%s/%s/rolesanywhere/aws4_request", t.Format("20060102"), c.region)
	c.credential = fmt.Sprintf("%s/%s", c.signingCert.SerialNumber, c.credScope)
	c.stringToSign = createStringToSign(c, t)
	err = getSignature(c, *req)
	if err != nil {
		return nil, err
	}

	addAuthHeader(req, "AWS4-X509-RSA-SHA256", c.credential, c.signature)
	req.Header.Add("content-type", "application/json")
	return req, nil
}

func createRequest(c *config, t time.Time) (*http.Request, error) {
	q := url.Values{}
	q.Set("profileArn", c.profileArn)
	q.Set("roleArn", c.roleArn)
	q.Set("trustAnchorArn", c.trustAnchorArn)
	url := fmt.Sprintf("https://rolesanywhere.%s.amazonaws.com/sessions?%s", c.region, q.Encode())
	req, err := http.NewRequest(http.MethodPost, url, http.NoBody)
	if err != nil {
		return nil, err
	}

	req.Header.Add("X-Amz-Date", t.UTC().Format("20060102T150405Z"))
	req.Header.Add("host", fmt.Sprintf("rolesanywhere.%s.amazonaws.com", c.region))
	req.Header.Add("X-Amz-X509", base64.StdEncoding.EncodeToString(c.signingCert.Raw))
	return req, nil
}

func addAuthHeader(req *http.Request, algorithm, credential, signature string) {
	signedHeaders := strings.Join(signedHeaders(*req), ";")
	authHeader := fmt.Sprintf("%s Credential=%s, SignedHeaders=%s, Signature=%s", algorithm, credential, signedHeaders, signature)
	req.Header.Set("Authorization", authHeader)
}

func getSignature(c *config, req http.Request) error {
	digest := makeHash(sha256.New(), []byte(c.stringToSign))

	signed, err := c.signingKey.Sign(rand.Reader, digest, crypto.SHA256)
	if err != nil {
		return err
	}
	c.signature = hex.EncodeToString(signed)
	return nil
}

func createCanonicalRequest(c *config, req http.Request) error {
	cHeaders := canonicalHeaders(req)
	hash, err := hashedPayload(req)
	if err != nil {
		return err
	}
	uri := getURIPath(req.URL)
	query := sortEncodeQueryString(req)
	c.canonicalRequest = fmt.Sprintf("%s\n%s\n%s\n%s%s", req.Method, uri, query, cHeaders, hash)
	c.canonicalRequestHashed = hex.EncodeToString(makeHash(sha256.New(), []byte(c.canonicalRequest)))
	return nil
}

func hashedPayload(req http.Request) (string, error) {
	body, err := ioutil.ReadAll(req.Body)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", sha256.Sum256(body)), nil
}

func canonicalHeaders(req http.Request) string {
	var cHeaders string
	header_keys := signedHeaders(req)
	for _, k := range header_keys {
		v := req.Header.Get(k)
		cHeaders += fmt.Sprintf("%s:%s\n", k, v)
	}
	signed_headers := strings.Join(header_keys, ";")
	return fmt.Sprintf("%s\n%s\n", cHeaders, signed_headers)
}

func signedHeaders(req http.Request) []string {
	var header_keys []string
	for k := range req.Header {
		header_keys = append(header_keys, strings.ToLower(k))
	}
	sort.Strings(header_keys)
	return header_keys
}

func createStringToSign(c *config, t time.Time) string {
	return fmt.Sprintf("AWS4-X509-RSA-SHA256\n%s\n%s\n%s", t.Format("20060102T150405Z"), c.credScope, c.canonicalRequestHashed)
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

func sortEncodeQueryString(req http.Request) string {
	query := req.URL.Query()
	for key := range query {
		sort.Strings(query[key])
	}
	return strings.ReplaceAll(query.Encode(), "+", "%20") 

}

func makeHash(hash hash.Hash, b []byte) []byte {
	hash.Reset()
	hash.Write(b)
	return hash.Sum(nil)
}
