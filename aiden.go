package sigv4

import (
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/aws/smithy-go/encoding/httpbinding"
	"golang.org/x/crypto/ssh"
)

func NewSignerFromSshSigner(in ssh.AlgorithmSigner) Signer {
	return &SSHSigner{AlgorithmSigner: in}
}

type SSHSigner struct {
	ssh.AlgorithmSigner
}

func (s *SSHSigner) Sign(rand io.Reader, message []byte) (signature []byte, err error) {
	typ := s.AlgorithmSigner.PublicKey().Type()

	switch typ {
	case ssh.KeyAlgoRSA:
		sig, err := s.AlgorithmSigner.SignWithAlgorithm(rand, message, ssh.KeyAlgoRSASHA256)
		if err != nil {
			return nil, fmt.Errorf("rsa-sha2-256 signing: %w", err)
		}

		return sig.Blob, nil
	case ssh.KeyAlgoECDSA256:
		type asn1Signature struct {
			R, S *big.Int
		}

		sig, err := s.AlgorithmSigner.SignWithAlgorithm(rand, message, ssh.KeyAlgoECDSA256)
		if err != nil {
			return nil, fmt.Errorf("ssh signing: %w", err)
		}

		asn1Sig := asn1Signature{}
		err = ssh.Unmarshal(sig.Blob, &asn1Sig)
		if err != nil {
			return nil, fmt.Errorf("unmarshalling ssh signature: %w", err)
		}

		realsig, err := asn1.Marshal(asn1Sig)
		if err != nil {
			return nil, fmt.Errorf("remarshalling crypto signature: %w", err)
		}

		return realsig, nil
	default:
		return nil, fmt.Errorf("unexpected ssh key type: %s", typ)
	}
}

func (s *SSHSigner) Public() crypto.PublicKey {
	//return s.AlgorithmSigner.PublicKey().(ssh.CryptoPublicKey).CryptoPublicKey()

	// we have to round-trip because the agent's key doesn't implement
	// ssh.CryptoPublicKey. maybe i should file a golang feature request?
	authorized := ssh.MarshalAuthorizedKey(s.AlgorithmSigner.PublicKey())
	pub, _, _, _, err := ssh.ParseAuthorizedKey(authorized)
	if err != nil {
		panic(err)
	}

	return pub.(ssh.CryptoPublicKey).CryptoPublicKey()
}

func signingAlgorithm(c *x509.Certificate) string {
	switch c.PublicKeyAlgorithm {
	case x509.RSA:
		return "AWS4-X509-RSA-SHA256"
	case x509.ECDSA:
		return "AWS4-X509-ECDSA-SHA256"
	default:
		panic("unsupported key algorithm")
	}
}

func SignHTTP(certificate *x509.Certificate, signer Signer, r *http.Request, payloadHash, service, region string, signingTime time.Time) error {
	s := &HttpSigner{
		Request:                r,
		PayloadHash:            payloadHash,
		ServiceName:            service,
		Region:                 region,
		Certificate:            certificate,
		Signer:                 signer,
		Time:                   signingTime.UTC(),
		DisableHeaderHoisting:  false,
		DisableURIPathEscaping: false,
	}

	err := s.Build()
	if err != nil {
		return err
	}

	return nil
}

type HttpSigner struct {
	Request     *http.Request
	ServiceName string
	Region      string
	Time        time.Time

	Certificate *x509.Certificate
	Signer      Signer

	PayloadHash string

	DisableHeaderHoisting  bool
	DisableURIPathEscaping bool
}

func (s *HttpSigner) Build() error {
	req := s.Request

	headers := req.Header

	s.setRequiredSigningFields(headers)
	query := req.URL.Query()
	// Sort Each Query Key's Values
	for key := range query {
		sort.Strings(query[key])
	}
	var rawQuery strings.Builder
	rawQuery.WriteString(strings.Replace(query.Encode(), "+", "%20", -1))

	credentialScope := s.buildCredentialScope()
	credentialStr := s.Certificate.SerialNumber.String() + "/" + credentialScope

	unsignedHeaders := headers

	host := req.URL.Host
	if len(req.Host) > 0 {
		host = req.Host
	}

	_, signedHeadersStr, canonicalHeaderStr := s.buildCanonicalHeaders(host, unsignedHeaders, s.Request.ContentLength)

	canonicalURI := getURIPath(req.URL)
	if !s.DisableURIPathEscaping {
		canonicalURI = httpbinding.EscapePath(canonicalURI, false)
	}

	canonicalString := s.buildCanonicalString(
		req.Method,
		canonicalURI,
		rawQuery.String(),
		signedHeadersStr,
		canonicalHeaderStr,
	)
	fmt.Println(canonicalString)
	strToSign := s.buildStringToSign(credentialScope, canonicalString)
	fmt.Println(strToSign)
	signingSignature, err := s.buildSignature(strToSign)
	if err != nil {
		return err
	}

	headers["Authorization"] = append(headers["Authorization"][:0], buildAuthorizationHeader(s.Certificate, credentialStr, signedHeadersStr, signingSignature))

	req.URL.RawQuery = rawQuery.String()

	return nil
}

func (s *HttpSigner) setRequiredSigningFields(headers http.Header) {
	headers["X-Amz-X509"] = []string{base64.StdEncoding.EncodeToString(s.Certificate.Raw)}

	amzDate := s.Time.Format("20060102T150405Z")
	headers["X-Amz-Date"] = append(headers["X-Amz-Date"][:0], amzDate)
}

func (s *HttpSigner) buildCredentialScope() string {
	return strings.Join([]string{
		s.Time.Format("20060102"),
		s.Region,
		s.ServiceName,
		"aws4_request",
	}, "/")
}

func (s *HttpSigner) buildCanonicalHeaders(host string, header http.Header, length int64) (signed http.Header, signedHeaders, canonicalHeadersStr string) {
	whitespaceCompressor := regexp.MustCompile(`\s+`)

	signed = make(http.Header)

	var headers []string
	const hostHeader = "host"
	headers = append(headers, hostHeader)
	signed[hostHeader] = append(signed[hostHeader], host)

	// const contentLengthHeader = "content-length"
	// if length > 0 {
	// 	headers = append(headers, contentLengthHeader)
	// 	signed[contentLengthHeader] = append(signed[contentLengthHeader], strconv.FormatInt(length, 10))
	// }

	for k, v := range header {
		lowerCaseKey := strings.ToLower(k)

		switch lowerCaseKey {
		case "authorization", "user-agent", "x-amzn-trace-id", "content-length":
			continue
		default:
			// no-op
		}

		if _, ok := signed[lowerCaseKey]; ok {
			// include additional values
			signed[lowerCaseKey] = append(signed[lowerCaseKey], v...)
			continue
		}

		headers = append(headers, lowerCaseKey)
		signed[lowerCaseKey] = v
	}
	sort.Strings(headers)

	signedHeaders = strings.Join(headers, ";")

	var canonicalHeaders strings.Builder
	n := len(headers)
	const colon = ':'
	for i := 0; i < n; i++ {
		if headers[i] == hostHeader {
			canonicalHeaders.WriteString(hostHeader)
			canonicalHeaders.WriteRune(colon)
			canonicalHeaders.WriteString(host)
		} else {
			canonicalHeaders.WriteString(headers[i])
			canonicalHeaders.WriteRune(colon)
			// Trim out leading, trailing, and dedup inner spaces from signed header values.
			values := signed[headers[i]]
			for j, v := range values {
				cleanedValue := strings.TrimSpace(whitespaceCompressor.ReplaceAllLiteralString(v, " "))
				canonicalHeaders.WriteString(cleanedValue)
				if j < len(values)-1 {
					canonicalHeaders.WriteRune(',')
				}
			}
		}
		canonicalHeaders.WriteRune('\n')
	}
	canonicalHeadersStr = canonicalHeaders.String()

	return signed, signedHeaders, canonicalHeadersStr
}

func (s *HttpSigner) buildCanonicalString(method, uri, query, signedHeaders, canonicalHeaders string) string {
	return strings.Join([]string{
		method,
		uri,
		query,
		canonicalHeaders,
		signedHeaders,
		s.PayloadHash,
	}, "\n")
}

func (s *HttpSigner) buildStringToSign(credentialScope, canonicalRequestString string) string {
	return strings.Join([]string{
		signingAlgorithm(s.Certificate),
		s.Time.Format("20060102T150405Z"),
		credentialScope,
		hex.EncodeToString(MakeHash(sha256.New(), []byte(canonicalRequestString))),
	}, "\n")
}

func (s *HttpSigner) buildSignature(strToSign string) (string, error) {
	signed, err := s.Signer.Sign(rand.Reader, []byte(strToSign))
	if err != nil {
		panic(err)
	}

	return hex.EncodeToString(signed), nil
}

func buildAuthorizationHeader(certificate *x509.Certificate, credentialStr, signedHeadersStr, signingSignature string) string {
	const credential = "Credential="
	const signedHeaders = "SignedHeaders="
	const signature = "Signature="
	const commaSpace = ", "

	algorithm := signingAlgorithm(certificate)

	var parts strings.Builder
	parts.Grow(len(algorithm) + 1 +
		len(credential) + len(credentialStr) + 2 +
		len(signedHeaders) + len(signedHeadersStr) + 2 +
		len(signature) + len(signingSignature),
	)
	parts.WriteString(algorithm)
	parts.WriteRune(' ')
	parts.WriteString(credential)
	parts.WriteString(credentialStr)
	parts.WriteString(commaSpace)
	parts.WriteString(signedHeaders)
	parts.WriteString(signedHeadersStr)
	parts.WriteString(commaSpace)
	parts.WriteString(signature)
	parts.WriteString(signingSignature)
	return parts.String()
}

// Signer is almost identical to crypto.Signer, but it expects to receive the
// raw message to be signed (rather than its digest). This is because ssh.Signer
// expects a raw undigested message too.
type Signer interface {
	Public() crypto.PublicKey
	Sign(rand io.Reader, undigestedMessage []byte) (signature []byte, err error)
}
