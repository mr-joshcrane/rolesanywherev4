package sigv4_test

import (
	"context"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"testing"
)

// import (
// 	"bytes"
// 	"encoding/json"
// 	"fmt"
// 	"io"
// 	"log"
// 	"net/http"
// 	"net/url"
// 	"strings"
// 	"testing"

// 	"github.com/google/go-cmp/cmp"
// 	"github.com/mr-joshcrane/sigv4"
// )

// func privateKey() string {
// 	return `-----BEGIN RSA PRIVATE KEY-----
// MIICSwIBAAJ9Y8EiHfxxM/nOn2SnI1XxDwOtBDT1JF0Qy9b1YJjuvb7ci10f5MVm
// TBYj1FSUfM9Moz2CUQYun2DYcWoHpP8ejHmAPUk5Wyp2Q7P+28unIHBJaTfeCOOz
// FRPV60GSYe36aRpm8/wUVmzxaK8kB9eZhO7quN7mId1/jVq3J88CAwEAAQJ9Uhfp
// KeBMkUeuAYLmAbCCd6bAxkuGyuxEHFzFB0AUidb+zTpQOwcxDsDRr7YDlUtMeLLw
// AhoiWEttFLj7nY+8/g67mTZvPLKdFdrYar6KAk01OIioFqFcbDPRr5iz7iEL5W0R
// MSdsLSD3RiYfhc27QB7qIBJoS7m24314AlECPw8xiZs/OPQoJ6kgv6lME4TK/Bwb
// cQf5yqeq5VKohnMAw7Kv+eThw5uKFS/JKbXyMUHtsJL5XzX3NDd++n3luwI/BpDK
// 66qUyqg7dQKQeaWFNarPUoSXIWZEFMvHaKxePpa/vTnvH0QfcRjBt1sWo0ZQmugu
// R4AtaOugi3+xcHr9Aj8L/YQjSJmh1a63Amk/KhKdUbP0WpOxP6h2+Z9QxD6Ws5u9
// gLMtth2wuiBOPer089V7uiEHXFWPOS+0PDli8dECPwTyzq6O8/RGlgGb/C5jbaJE
// alxEaPAYdwnBiTtAZwv/bOZ/KtZC7vu78A11TvuivI/0nSTw28jvhyJ9DMy9NQI/
// AMNaA0JjBPWi0Y197mXIB8/6U3qgzjSEOhEviOpLcq5XSFd98RtfCo+3gco7TS7P
// ak7FjXD29tHPt5musF7G
// -----END RSA PRIVATE KEY-----
// `
// }

// func derCert() string {
// 	return "MO+/vQJSMO+/vQHvv70CAgrvv70wCgYJKu+/vUjvv73vv70KAQEFBe+/vTDvv73vv70xCzAJBgNVBAYTAkpQMQ4wDAYDVQQIEwVUb2t5bzEQMA4GA1UEBxMHQ2h1by1rdTERMA8GA1UEChMIRnJhbms0REQxGDAWBgNVBAsTD1dlYkNlcnQgU3VwcG9ydDEYMBYGA1UEAxMPRnJhbms0REQgV2ViIENBMSMwIQYJKu+/vUjvv73vv70KAQkBFhRzdXBwb3J0QGZyYW5rNGRkLmNvbTAeFwoxMzAxMTEwNDUxMzlaFwoxODAxMTAwNDUxMzlaMEsxCzAJBgNVBAYMAkpQMQ8wCgYDVQQIDAZcVG9reW8xETAPBgNVBAoMCEZyYW5rNEREMRgwFgYDVQQDDA93d3cuZXhhbXBsZS5jb20w77+977+9MAoGCSrvv71I77+977+9CgEBAQXvv70D77+977+977+9MO+/ve+/vQJ9Y++/vSId77+9cTPvv73On2Tvv70jVe+/vQ8D77+9BDTvv70kXRDvv73vv73vv71g77+97r2+3ItdH++/ve+/vWZMFiPvv71U77+9fO+/vUzvv70977+9UQYu77+9YO+/vXFqB++/ve+/vR7vv71577+9PUk5Wyp2Q++/ve+/ve+/vcunIHBJaTfvv70I77+9FRPvv73vv71B77+9Ye+/ve+/vWkaZu+/ve+/vRRWbO+/vWjvv70kB9eZ77+977+977+977+977+9Ie+/vX/vv71a77+9J++/vQIDAe+/vQEwCgYJKu+/vUjvv73vv70KAQEFBe+/vQPvv73vv73vv70Mfy4377+9zLzvv73vv705V1vvv71xHwrvv73vv70ZIwnvv71cFA7vv70UN++/vdqH77+977+9GE3vv71qMT9Z77+9Zu+/vXvvv73vv73vv71h77+9Q39XWe+/vUPvv70F77+977+9Ne+/vSDJpg9777+977+9MVvvv73vv73vv73vv70YGH7vv71Zde+/vR7vv71SUDHvv70V77+9Fe+/ve+/vd+W77+9FDHvv70Q77+9N++/ve+/vSPvv73vv73vv71mdu+/ve+/ve+/ve+/ve+/ve+/ve+/vRfvv70fETzvv73evz9/MA=="
// }

// func testRequest() http.Request {
// 	body := sigv4.RequestBody{
// 		DurationSeconds: 1,
// 		ProfileArn:      "some::profile::arn",
// 		RoleArn:         "some::role::arn",
// 		SessionName:     "sessionname",
// 		TrustAnchorArn:  "someTrustAnchor",
// 	}
// 	var buf bytes.Buffer
// 	err := json.NewEncoder(&buf).Encode(body)
// 	if err != nil {
// 		log.Fatal(err)
// 	}
// 	b := io.NopCloser(&buf)

// 	req := http.Request{
// 		Method: http.MethodPost,
// 		Host:   "iam.amazonaws.com",
// 		URL:    &url.URL{Scheme: "https", Path: "iam.amazonaws.com/", RawQuery: "Action=ListUsers&Version=2010-05-08"},
// 		Header: http.Header{},
// 		Body:   b,
// 	}
// 	req.Header.Add("content-type", "application/x-www-form-urlencoded; charset=utf-8")
// 	req.Header.Add("X-Amz-Date", "20150830T123600Z")
// 	req.Header.Add("host", "iam.amazonaws.com")
// 	req.Header.Add("X-Amz-X509", derCert())
// 	return req
// }

// func TestCreateCanonicalRequest(t *testing.T) {
// 	t.Parallel()
// 	want := fmt.Sprintf(`POST
// /
// Action=ListUsers&Version=2010-05-08
// content-type:application/x-www-form-urlencoded; charset=utf-8
// host:iam.amazonaws.com
// x-amz-date:20150830T123600Z
// x-amz-x509:%s

// content-type;host;x-amz-date;x-amz-x509
// 8f407b211ebd9453031c472ae413a0cddef15e188e9ec5c7c7f7c09e33752b69`, derCert())

// 	req := testRequest()

// 	got := sigv4.CreateCanonicalRequest(req)
// 	if want != got {
// 		t.Fatalf(cmp.Diff(want, got))
// 	}
// }

// func TestHashCanonicalRequest(t *testing.T) {
// 	t.Parallel()
// 	cr := `POST
// /
// Action=ListUsers&Version=2010-05-08
// content-type:application/x-www-form-urlencoded; charset=utf-8
// host:iam.amazonaws.com
// x-amz-date:20150830T123600Z

// content-type;host;x-amz-date
// e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`

// 	want := "e076194ea8f160afbbb465501645fc3566d64edb27c2fe8eb748934561867d2e"
// 	got := sigv4.HashedCanonicalRequest(cr)
// 	if want != got {
// 		t.Fatalf(cmp.Diff(want, got))
// 	}
// }

// func TestCreateStringToSign(t *testing.T) {
// 	t.Parallel()
// 	want := `AWS4-X509-RSA-SHA256
// 20150830T123600Z
// 20150830/us-east-1/iam/aws4_request
// f536975d06c0309214f805bb90ccff089219ecd68b2577efef23edd43b7e1a59`
// 	req := testRequest()
// 	credScope := "20150830/us-east-1/iam/aws4_request"
// 	hashedCR := "f536975d06c0309214f805bb90ccff089219ecd68b2577efef23edd43b7e1a59"
// 	got := sigv4.CreateStringToSign(req, credScope, hashedCR)
// 	if want != got {
// 		t.Fatalf(cmp.Diff(want, got))
// 	}
// }

// func TestGetSignature(t *testing.T) {
// 	t.Parallel()
// 	stringToSign := `AWS4-X509-RSA-SHA256
// 20150830T123600Z
// 20150830/us-east-1/iam/aws4_request
// f536975d06c0309214f805bb90ccff089219ecd68b2577efef23edd43b7e1a59`
// 	req := testRequest()
// 	want := "21ef467134811b5fde8e134e68e98d85d40e8b2d30225d507c8e9674c2acf56b78a49d930ac86c01a53bcbe8d9ac18c5a1f2374ede6b81dfb68c169aae36907c4eb3e1b082b2283939b91c8b80f5c547e773e5331857c7067817bb63142efc0bb23663cfbde0e04a3a34c35f6a64b492b21fc018ecbf9cb5ff04cd151c"
// 	got := sigv4.GetSignature(req, stringToSign, privateKey())
// 	if want != got {
// 		t.Fatalf(cmp.Diff(want, got))
// 	}
// }

// func TestCreateAuthorization(t *testing.T) {
// 	t.Parallel()
// 	req := testRequest()
// 	algorithm := "AWS4-X509-RSA-SHA256"
// 	certSerial := "CERTIFICATESERIALNUMBER"
// 	credScope := "20150830/us-east-1/iam/aws4_request"
// 	credential := fmt.Sprintf("%s/%s", certSerial, credScope)
// 	signedHeaders := strings.Join(sigv4.SignedHeaders(req), ";")
// 	signature := "bf336ef349a108bd9d6764b6b5202e90120038281f3774b363ff31e51a74b7e2"
// 	want := "AWS4-X509-RSA-SHA256 Credential=CERTIFICATESERIALNUMBER/20150830/us-east-1/iam/aws4_request, SignedHeaders=content-type;host;x-amz-date;x-amz-x509, Signature=bf336ef349a108bd9d6764b6b5202e90120038281f3774b363ff31e51a74b7e2"
// 	got := sigv4.CreateAuthorization(algorithm, credential, signedHeaders, signature)
// 	if want != got {
// 		t.Fatalf(cmp.Diff(want, got))
// 	}
// }

func TestCerts(t *testing.T) {
	
}
