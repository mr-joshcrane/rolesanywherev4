package sigv4

import (
	"crypto/sha256"
	"fmt"
	"io/ioutil"
	"net/http"
	"sort"
	"strings"
)

func CreateCanonicalRequest(req http.Request) string {
	cr := ""
	cr += req.Method + "\n"
	cr += "/" + req.RequestURI + "\n"
	cr += req.URL.RawQuery + "\n"
	cr += CanonicalHeaders(req)

	body, err := ioutil.ReadAll(req.Body)
	if err != nil {
		panic(err)
	}
	hashedCr := fmt.Sprintf("%x", sha256.Sum256(body))
	cr += hashedCr
	return cr
}

func CanonicalHeaders(req http.Request) string {
	ch := ""
	req.Header.Set("host", req.Host)
	header_keys := []string{}
	for k := range req.Header {
		header_keys = append(header_keys, strings.ToLower(k))
	}
	sort.Strings(header_keys)
	for _, k := range header_keys {
		v := req.Header.Get(k)
		ch += fmt.Sprintf("%s:%s\n", k, v)
	}
	ch += "\n"
	ch += strings.Join(header_keys, ";")
	ch += "\n"
	return ch
}
