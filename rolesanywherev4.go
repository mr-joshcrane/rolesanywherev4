package rolesanywherev4

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"
)

var Now = time.Now

func AssumeRole(profileArn, roleArn, trustAnchorArn, region string, signingCert *x509.Certificate, signingKey *rsa.PrivateKey) (accessKeyId, secretAccessKey, sessionToken string, err error) {
	req, err := NewRolesAnywhereRequest(profileArn, roleArn, trustAnchorArn, region, signingCert, signingKey)
	if err != nil {
		return "", "", "", err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", "", "", err
	}
	defer resp.Body.Close()
	var r struct{
		CredentialSet struct {
			Credentials struct {
				AccessKeyId     string
				SecretAccessKey string
				SessionToken    string
			}
		}
	}
	io.Copy(os.Stdout, resp.Body)
	err = json.NewDecoder(resp.Body).Decode(&r)
	if err != nil {
		return "", "", "", err
	}
	return r.CredentialSet.Credentials.AccessKeyId, r.CredentialSet.Credentials.SecretAccessKey, r.CredentialSet.Credentials.SessionToken, nil
}

func NewRolesAnywhereRequest(profileArn, roleArn, trustAnchorArn, region string, signingCert *x509.Certificate, signingKey *rsa.PrivateKey) (*http.Request, error) {
	const signingAlgorithm = "AWS4-X509-RSA-SHA256"
	t := Now().UTC()
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

	if err != nil {
		return nil, err
	}

	cHeaders := canonicalHeaders(*req)
	hash, err := hashedPayload(*req)
	if err != nil {
		return nil, err
	}
	uri := getURIPath(req.URL)
	query := sortEncodeQueryString(*req)
	canonicalRequest := fmt.Sprintf("%s\n%s\n%s\n%s%s", req.Method, uri, query, cHeaders, hash)
	canonicalRequestHashed := hex.EncodeToString(makeHash(sha256.New(), []byte(canonicalRequest)))
	credScope := fmt.Sprintf("%s/%s/rolesanywhere/aws4_request", t.Format("20060102"), region)
	credential := fmt.Sprintf("%s/%s", signingCert.SerialNumber, credScope)
	stringToSign := fmt.Sprintf("%s\n%s\n%s\n%s", signingAlgorithm, t.Format("20060102T150405Z"), credScope, canonicalRequestHashed)
	digest := sha256.Sum256([]byte(stringToSign))
	signed, err := signingKey.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		return nil, err
	}
	signature := hex.EncodeToString(signed)
	if err != nil {
		return nil, err
	}
	signedHeaders := strings.Join(signedHeaders(*req), ";")
	authHeader := fmt.Sprintf("%s Credential=%s, SignedHeaders=%s, Signature=%s", signingAlgorithm, credential, signedHeaders, signature)
	req.Header.Set("Authorization", authHeader)
	req.Header.Add("content-type", "application/json")
	return req, nil
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
