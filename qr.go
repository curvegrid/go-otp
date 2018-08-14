package otp

import (
	"encoding/base32"
	"fmt"
	"net/url"
	"rsc.io/qr"
)

// Taken from https://github.com/gokyle/twofactor/blob/master/oath.go
// and modified

// URL constructs a URL appropriate for the token (i.e. for use in a
// QR code).
// URI keys specified here: https://github.com/google/google-authenticator/wiki/Key-Uri-Format
func (t *TOTP) URL(label, issuer string) string {
	var secret string
	if t.IsBase32Secret {
		secret = base32.StdEncoding.EncodeToString([]byte(t.Secret))
	} else {
		secret = t.Secret
	}
	u := url.URL{}
	v := url.Values{}
	u.Scheme = "otpauth"
	u.Host = "totp"

	u.Path = label
	v.Add("secret", secret)
	v.Add("digits", fmt.Sprintf("%d", t.Length))
	v.Add("algorithm", "SHA1")

	v.Add("issuer", issuer) // do I need this?

	u.RawQuery = v.Encode()
	return u.String()
}

// QR generates a byte slice containing the a QR code encoded as a
// PNG with level Q error correction.
func (t *TOTP) QR(label, issuer string) ([]byte, error) {
	u := t.URL(label, issuer)
	code, err := qr.Encode(u, qr.Q)
	if err != nil {
		return nil, err
	}
	return code.PNG(), nil
}
