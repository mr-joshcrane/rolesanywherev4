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
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
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
	var r struct {
		Message       string
		CredentialSet []struct {
			Credentials struct {
				AccessKeyId     string
				SecretAccessKey string
				SessionToken    string
			}
		}
	}

	err = json.NewDecoder(resp.Body).Decode(&r)
	if err != nil {
		return "", "", "", err
	}
	if r.Message != "" {
		return "", "", "", errors.New(r.Message)
	}
	return r.CredentialSet[0].Credentials.AccessKeyId, r.CredentialSet[0].Credentials.SecretAccessKey, r.CredentialSet[0].Credentials.SessionToken, nil
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
	body, err := ioutil.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}
	payloadHash := fmt.Sprintf("%x", sha256.Sum256(body))

	if err != nil {
		return nil, err
	}
	uri := getURIPath(req.URL)
	query := sortEncodeQueryString(*req)
	canonicalRequest := fmt.Sprintf("%s\n%s\n%s\n%s%s", req.Method, uri, query, cHeaders, payloadHash)
	h := sha256.Sum256([]byte(canonicalRequest))
	canonicalRequestHashed := hex.EncodeToString(h[:])
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
