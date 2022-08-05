package main

import (
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/mr-joshcrane/sigv4"
)

func main() {
	profileArn := "arn:aws:rolesanywhere:ap-southeast-2:038021827431:profile/9419ce03-14c5-41e5-b0bc-62e717c53092"
	roleArn := "arn:aws:iam::038021827431:role/TestRole"
	trustAnchorArn := "arn:aws:rolesanywhere:ap-southeast-2:038021827431:trust-anchor/8f916267-7377-4d5d-a6f6-0b03f3feed3c"
	region := "ap-southeast-2"
	signingCertPath := "./certs/inter.pem"
	signingKeyPath := "./certs/inter_key.pem"

	req, err := sigv4.SignedRequest(region, profileArn, roleArn, trustAnchorArn, signingCertPath, signingKeyPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	bdy, _ := io.ReadAll(resp.Body)
	fmt.Println(string(bdy))

}

// Take profileArn, roleArn, trustAnchorArn as url.Values
// Create a post request
// read in cert
// read in key
// Attach the headers
// authorize the request
