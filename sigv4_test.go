package sigv4_test

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/mr-joshcrane/sigv4"
)

func testRequest() http.Request {
	req := http.Request{
		Method: http.MethodGet,
		Host:   "iam.amazonaws.com",
		URL:    &url.URL{Scheme: "https", Path: "iam.amazonaws.com/", RawQuery: "Action=ListUsers&Version=2010-05-08"},
		Header: http.Header{},
		Body:   http.NoBody,
	}
	req.Header.Add("content-type", "application/x-www-form-urlencoded; charset=utf-8")
	req.Header.Add("X-Amz-Date", "20150830T123600Z")
	return req
}

func TestCreateCanonicalRequest(t *testing.T) {
	want := `GET
/
Action=ListUsers&Version=2010-05-08
content-type:application/x-www-form-urlencoded; charset=utf-8
host:iam.amazonaws.com
x-amz-date:20150830T123600Z

content-type;host;x-amz-date
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`

	req := testRequest()

	got := sigv4.CreateCanonicalRequest(req)
	if want != got {
		t.Fatalf(cmp.Diff(want, got))
	}
}

func TestHashCanonicalRequest(t *testing.T) {
	t.Parallel()
	cr := `GET
/
Action=ListUsers&Version=2010-05-08
content-type:application/x-www-form-urlencoded; charset=utf-8
host:iam.amazonaws.com
x-amz-date:20150830T123600Z

content-type;host;x-amz-date
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`

	want := "f536975d06c0309214f805bb90ccff089219ecd68b2577efef23edd43b7e1a59"
	got := sigv4.HashedCanonicalRequest(cr)
	if want != got {
		t.Fatalf(cmp.Diff(want, got))
	}
}

func TestCreateStringToSign(t *testing.T) {
	t.Parallel()
	want := `AWS4-HMAC-SHA256
20150830T123600Z
20150830/us-east-1/iam/aws4_request
f536975d06c0309214f805bb90ccff089219ecd68b2577efef23edd43b7e1a59`
	req := testRequest()
	credScope := "20150830/us-east-1/iam/aws4_request"
	hashedCR := "f536975d06c0309214f805bb90ccff089219ecd68b2577efef23edd43b7e1a59"
	got := sigv4.CreateStringToSign(req, credScope, hashedCR)
	if want != got {
		t.Fatalf(cmp.Diff(want, got))
	}
}

func TestGetSignature(t *testing.T) {
	t.Parallel()
	stringToSign := `AWS4-HMAC-SHA256
20150830T123600Z
20150830/us-east-1/iam/aws4_request
f536975d06c0309214f805bb90ccff089219ecd68b2577efef23edd43b7e1a59`
	want := "bf336ef349a108bd9d6764b6b5202e90120038281f3774b363ff31e51a74b7e2"
	got := sigv4.GetSignature(stringToSign)
	if want != got {
		t.Fatalf(cmp.Diff(want, got))
	}
}

func TestCreateAuthorization(t *testing.T) {
	t.Parallel()
	req := testRequest()
	algorithm := "AWS4-X509-RSA-SHA256"
	certSerial := "CERTIFICATESERIALNUMBER"
	credScope := "20150830/us-east-1/iam/aws4_request"
	credential := fmt.Sprintf("%s/%s", certSerial, credScope)
	signedHeaders := strings.Join(sigv4.SignedHeaders(req), ";")
	signature := "bf336ef349a108bd9d6764b6b5202e90120038281f3774b363ff31e51a74b7e2"
	want := ""
	got := sigv4.CreateAuthorization(algorithm, credential, signedHeaders, signature)
	if want != got {
		t.Fatalf(cmp.Diff(want, got))
	}
}
