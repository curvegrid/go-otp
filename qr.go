package otp

import (
	"fmt"
	"net/url"
	"rsc.io/qr"
)

// Taken from https://github.com/gokyle/twofactor/blob/master/oath.go
// and modified

// URL constructs a URL appropriate for the token (i.e. for use in a
// QR code).
// URI keys specified here: https://github.com/google/google-authenticator/wiki/Key-Uri-Format
// Typically label is the username for the service, and issuer is the service name
func (t *TOTP) URL(label, issuer string) string {
	u := url.URL{}
	v := url.Values{}
	u.Scheme = "otpauth"
	u.Host = "totp"

	u.Path = label
	v.Add("secret", t.Secret)
	v.Add("digits", fmt.Sprintf("%d", t.Length))
	v.Add("algorithm", "SHA1")
	v.Add("issuer", issuer)

	u.RawQuery = v.Encode()
	return u.String()
}

// QR generates a byte slice containing the a QR code encoded as a
// PNG with level L (20%) error correction. Note that size of the image is a factor of the amount of data encoded as well as error correction
func (t *TOTP) QR(label, issuer string) ([]byte, error) {
	u := t.URL(label, issuer)
	code, err := qr.Encode(u, qr.L)
	if err != nil {
		return nil, err
	}
	return code.PNG(), nil
}
