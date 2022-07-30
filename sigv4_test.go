package sigv4_test

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/mr-joshcrane/sigv4"
)

func TestCreateCanonicalRequest(t *testing.T) {
	want := `GET
/
Action=ListUsers&Version=2010-05-08
content-type:application/x-www-form-urlencoded; charset=utf-8
host:iam.amazonaws.com
x-amz-date:20150830T123600Z

content-type;host;x-amz-date
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`

	req := http.Request{
		Method: http.MethodGet,
		Host:   "iam.amazonaws.com",
		URL:    &url.URL{Scheme: "https", Path: "iam.amazonaws.com/", RawQuery: "Action=ListUsers&Version=2010-05-08"},
		Header: http.Header{},
		Body:   http.NoBody,
	}
	req.Header.Add("content-type", "application/x-www-form-urlencoded; charset=utf-8")
	req.Header.Add("X-Amz-Date", "20150830T123600Z")

	got := sigv4.CreateCanonicalRequest(req)
	if want != got {
		t.Fatalf(cmp.Diff(want, got))
	}
}

// func CreateStringToSign(t *testing.T) {

// }

// func TestSignSigv4(t *testing.T) {

// }

// func DeriveSigningKey(t *testing.T) {

// }

// func CreateSignature(t *testing.T) {

// }

// func AddSignatureToRequest(t *testing.T) {

// }
