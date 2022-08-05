package sigv4_test

import (
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/mr-joshcrane/sigv4"
)

func TestSignRequest(t *testing.T) {
	t.Parallel()
	sigv4.Now = func() time.Time {
		return time.Date(2000, 1, 1, 1, 1, 1, 1, time.UTC)
	}
	profileArn := "arn:aws:rolesanywhere:ap-southeast-2:123456789012:profile/9419ce03-14c5-41e5-b0bc-62e717c53092"
	roleArn := "arn:aws:iam::123456789012:role/TestRole"
	trustAnchorArn := "arn:aws:rolesanywhere:ap-southeast-2:123456789012:trust-anchor/8f916267-7377-4d5d-a6f6-0b03f3feed3c"
	region := "ap-southeast-2"
	signingCertPath := "./certs/inter.pem"
	signingKeyPath := "./certs/inter_key.pem"

	signingCert, signingKey, err := sigv4.LoadCertsKeys(signingCertPath, signingKeyPath)
	if err != nil {
		t.Fatal(err)
	}

	req, err := sigv4.SignRequest(region, profileArn, roleArn, trustAnchorArn, signingCert, signingKey)
	if err != nil {
		t.Fatal(err)
	}

	want := "AWS4-X509-RSA-SHA256 Credential=2/20000101/ap-southeast-2/rolesanywhere/aws4_request, SignedHeaders=host;x-amz-date;x-amz-x509, Signature=1ae8d28706c17ae0878bb0dcab0ec7975f1c49a82a80c7a4eb6fa7cfc4b8bce64607fd9965dd119a27fbc39065fa30600872575005b6ccf39c2d4fa7a92d9d7c7953d41bb06f3b44e19b0b410f0c62f2b7f838c9158281cbae4489ea4152ee101ffb0827bad7d9bc7bf52b1351f9a0f2628b4a10c0991e6e2b84a22e9729e73d4b270cec046682036c03a33ce4f8a6b76a82f0146c70c64568df5899aab455af27dffc8b9cbb920fd3d97e323d0d3fcbd71eff7a6677821ae5842c5ffab5bca77171c8af2127733c03e1cad18199f6e3d4cd53cbafcc6913da35708d6c40e3d107274d094a892d9c56fe70424ba057241e47f4e23ff55577efa1da2b43284f38"
	got := req.Header.Get("Authorization")
	if want != got {
		t.Fatalf(cmp.Diff(want, got))
	}
}
