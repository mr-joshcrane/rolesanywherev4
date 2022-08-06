package rolesanywherev4_test

import (
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/mr-joshcrane/rolesanywherev4"
)

func TestSignRequest(t *testing.T) {
	t.Parallel()
	rolesanywherev4.Now = func() time.Time {
		return time.Date(2000, 1, 1, 1, 1, 1, 1, time.UTC)
	}
	profileArn := "arn:aws:rolesanywhere:ap-southeast-2:123456789012:profile/9419ce03-14c5-41e5-b0bc-62e717c53092"
	roleArn := "arn:aws:iam::123456789012:role/TestRole"
	trustAnchorArn := "arn:aws:rolesanywhere:ap-southeast-2:123456789012:trust-anchor/8f916267-7377-4d5d-a6f6-0b03f3feed3c"
	region := "ap-southeast-2"
	signingCert, err := Cert()
	if err != nil {
		t.Fatal(err)
	}

	signingKey, err := Key()
	if err != nil {
		t.Fatal(err)
	}
	config := rolesanywherev4.NewRolesAnywhereConfig(
		profileArn,
		roleArn,
		trustAnchorArn,
		region,
		signingCert,
		signingKey,
	)

	req, err := rolesanywherev4.SignRequest(config)
	if err != nil {
		t.Fatal(err)
	}

	want := "AWS4-X509-RSA-SHA256 Credential=2/20000101/ap-southeast-2/rolesanywhere/aws4_request, SignedHeaders=host;x-amz-date;x-amz-x509, Signature=60e605c8436fe98f19bed796d6e6555337b12ebf8f3e2ea17f83b58a1de156002e5bd218692906639abe0f69c4765b137e35641bfa66c7f6cf2f48251369dbab12e83cdf94d4f2eedb8496c2fc219bc7cb4bb2725451e264f9f90da18591f8e089edaa5d585cb790169491e5131c3127bc55897a4fc99121fdfee0ae854db3038573c3e01007a993932df8f5a0cdf94c2ee651893f30e8c4ed5a94afd81b4e05a24d16f36a71185196a22e381bd47daaeafd38b66bb388c9ceda6695f8fe34b4d97e1603b1caf549dd1260f0be9b0a8e8da5cfeb5d5356222550bb58b7dd752651e0aa23012a1256d83020ad07397dde0c5d47f94d618774c02d1404746b8cae"
	got := req.Header.Get("Authorization")
	if want != got {
		t.Fatalf(cmp.Diff(want, got))
	}
}
