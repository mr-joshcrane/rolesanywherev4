package sigv4

import (
	"crypto/sha256"
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
	return fmt.Sprintf("AWS4-HMAC-SHA256\n%s\n%s\n%s", requestTimestamp, credScope, hashedCR)
}

func GetSignature(stringToSign string) string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(stringToSign)))
}

func SignRequest(req *http.Request, auth string) {
	req.Header.Set("Authorization", auth)
}

func CreateAuthorization(algorithm string, credential string, signedHeaders string, signature string) string {
	return fmt.Sprintf("%s Credential=%s, SignedHeaders=%s, Signature=%s", algorithm, credential, signedHeaders, signature)
}
