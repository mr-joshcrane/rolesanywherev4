package main

import (
	"fmt"
	"os"

	"github.com/mr-joshcrane/rolesanywherev4"
)

func main() {
	profileArn := "arn:aws:rolesanywhere:ap-southeast-2:123456789012:profile/9419ce03-14c5-41e5-b0bc-62e717c53092"
	roleArn := "arn:aws:iam::123456789012:role/TestRole"
	trustAnchorArn := "arn:aws:rolesanywhere:ap-southeast-2:123456789012:trust-anchor/8f916267-7377-4d5d-a6f6-0b03f3feed3c"
	region := "ap-southeast-2"
	signingCertPath := "./certs/inter.pem"
	signingKeyPath := "./certs/inter_key.pem"

	signingCert, err := rolesanywherev4.LoadSigningCert(signingCertPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	signingKey, err := rolesanywherev4.LoadSigningKey(signingKeyPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	key, secret, session, err := rolesanywherev4.AssumeRole(profileArn, roleArn, trustAnchorArn, region, signingCert, signingKey)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stdout, "export AWS_ACCESS_KEY_ID=%s\n", key)
	fmt.Fprintf(os.Stdout, "export AWS_SECRET_ACCESS_KEY=%s\n", secret)
	fmt.Fprintf(os.Stdout, "export AWS_SESSION_TOKEN=%s\n", session)
}
