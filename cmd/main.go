package main

import (
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/mr-joshcrane/sigv4"
)

func main() {

	q := url.Values{}
	q.Set("profileArn", "arn:aws:rolesanywhere:ap-southeast-2:038021827431:profile/9419ce03-14c5-41e5-b0bc-62e717c53092")
	q.Set("roleArn", "arn:aws:iam::038021827431:role/TestRole")
	q.Set("trustAnchorArn", "arn:aws:rolesanywhere:ap-southeast-2:038021827431:trust-anchor/8f916267-7377-4d5d-a6f6-0b03f3feed3c")
	u := fmt.Sprintf("https://rolesanywhere.ap-southeast-2.amazonaws.com/sessions?%s", q.Encode())

	req, err := http.NewRequest(http.MethodPost, u, http.NoBody)
	if err != nil {
		panic(err)
	}
	t := time.Now()
	req.Header.Add("content-type", "application/json")
	req.Header.Add("X-Amz-Date", t.Format("20060102T150405Z"))
	req.Header.Add("host", "rolesanywhere.ap-southeast-2.amazonaws.com")
	
	certPEM, err := ioutil.ReadFile("./certs/inter.pem")
	if err != nil {
		panic(err)
	}
	cert, _ := pem.Decode(certPEM)

	req.Header.Add("X-Amz-X509", base64.StdEncoding.EncodeToString(cert.Bytes))

	keyPEM, err := ioutil.ReadFile("./certs/inter_key.pem")
	if err != nil {
		panic(err)
	}
	signedHeaders := strings.Join(sigv4.SignedHeaders(*req), ";")
	cr := sigv4.CreateCanonicalRequest(*req)
	fmt.Println(cr)

	certSerial := "2"

	credScope := t.Format("20060102") + "/ap-southeast-2/rolesanywhere/aws4_request"
	hash := sigv4.HashedCanonicalRequest(cr)
	stringToSign := sigv4.CreateStringToSign(*req, credScope, hash)

	fmt.Println(stringToSign)

	credential := fmt.Sprintf("%s/%s", certSerial, credScope)
	signature := sigv4.GetSignature(*req, stringToSign, keyPEM)
	auth := sigv4.CreateAuthorization("AWS4-X509-RSA-SHA256", credential, signedHeaders, signature)
	req.Header.Set("Authorization", auth)
	client := &http.Client{}

	// fmt.Println(req)
	resp, err := client.Do(req)
	fmt.Println(resp, err)
	bdy, _ := io.ReadAll(resp.Body)
	fmt.Println(string(bdy))
}
