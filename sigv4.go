package sigv4

import (
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"hash"
	"io/ioutil"
	"net/http"
	"net/url"
	"sort"
	"strings"
)

func HashedCanonicalRequest(cr string) string {
	x := fmt.Sprintf("%x", sha256.Sum256([]byte(cr)))
	return hex.EncodeToString([]byte(x))
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

func CreateStringToSign(req http.Request, credScope string, hashedCR string) string {
	requestTimestamp := req.Header.Get("x-amz-date")
	return fmt.Sprintf("AWS4-X509-RSA-SHA256\n%s\n%s\n%s", requestTimestamp, credScope, hashedCR)
}

func GetSignature(req http.Request, stringToSign string, privateKey []byte) string {
	p, _ := pem.Decode(privateKey)
	parsedKey, err := x509.ParsePKCS1PrivateKey(p.Bytes)
	if err != nil {
		panic(err)
	}
	digest := makeHash(sha256.New(), []byte(stringToSign))
	signed, err := parsedKey.Sign(rand.Reader, digest, crypto.SHA256)
	if err != nil {
		panic(err)
	}
	return hex.EncodeToString(signed)
}

func SignRequest(req *http.Request, auth string) {
	req.Header.Set("Authorization", auth)
}

func CreateAuthorization(algorithm string, credential string, signedHeaders string, signature string) string {
	x := fmt.Sprintf("%s Credential=%s, SignedHeaders=%s, Signature=%s", algorithm, credential, signedHeaders, signature)
	fmt.Println("$$$" + x)
	println()
	return x
}

type RequestBody struct {
	DurationSeconds int
	ProfileArn      string
	RoleArn         string
	SessionName     string
	TrustAnchorArn  string
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

	return rawQuery.String()
}

func makeHash(hash hash.Hash, b []byte) []byte {
	hash.Reset()
	hash.Write(b)
	return hash.Sum(nil)
}
