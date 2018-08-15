package otp

import (
	"bytes"
	"io/ioutil"
	"testing"
)

var cases = []struct {
	Secret         string
	IsBase32Secret bool
	Label          string
	Issuer         string
	ExpectedURL    string
	ExpectedQR     string
	QRError        error
	Digits         uint8
}{
	{
		Secret:         "JFKHQ4BZGQ4UEU2ZKJBEONCYIRAUYWLHNBGVO2RVPE2XGSLPJRQUWVJVLFKXAODPGZ5FENTVN54ES3SUMNSWC5ZXKJLUOTLQMNDHU6CMGNUHSMLLIJFTIMDSOJUFS42BJJTUG6KRG5DFMRT2IR3EGNSVKJVWOQ2I",
		IsBase32Secret: true,
		Issuer:         "COOL APP",
		Label:          "ann@example.com",
		ExpectedURL:    "otpauth://totp/ann@example.com?algorithm=SHA1&digits=6&issuer=COOL+APP&secret=JJDEWSCRGRBFUR2RGRKUKVJSLJFUUQSFJ5HEGWKJKJAVKWKXJREE4QSHKZHTEUSWKBCTEWCHKNGFASSSKFKVOVSKKZGEMS2YIFHUIUCHLI2UMRKOKRLE4NJUIVJTGU2VJVHFGV2DGVNFQS2KJRKU6VCMKFGU4RCIKU3EGTKHJZKUQU2NJRGESSSGKREU2RCTJ5FFKRSTGQZEESSKKRKUONSLKJDTKRCGJVJFIMSJKIZUKR2OKNLEWSSWK5HVCMSJ",
		ExpectedQR:     "test/cool_app.png",
		QRError:        nil,
		Digits:         6,
	},
	{
		Secret:         "FuY0c4SdIapPYOf3ZZmOEECpBkTf6UV00scbzvIFwOBV9r6g0wQHGhg9NO1vtEtsRLAH3SEw9j45Fe9QvuBeNBgH6h8nJj4qbWAp",
		IsBase32Secret: false,
		Issuer:         "SUIKA DENSHA",
		Label:          "watermelon@example.com",
		ExpectedURL:    "otpauth://totp/watermelon@example.com?algorithm=SHA1&digits=10&issuer=SUIKA+DENSHA&secret=FuY0c4SdIapPYOf3ZZmOEECpBkTf6UV00scbzvIFwOBV9r6g0wQHGhg9NO1vtEtsRLAH3SEw9j45Fe9QvuBeNBgH6h8nJj4qbWAp",
		ExpectedQR:     "test/suika_densha.png",
		QRError:        nil,
		Digits:         10,
	},
}

func TestURL(t *testing.T) {
	for _, c := range cases {
		totp := &TOTP{Secret: c.Secret, IsBase32Secret: c.IsBase32Secret, Length: c.Digits}
		totp.Get()

		actual := totp.URL(c.Label, c.Issuer)
		if actual != c.ExpectedURL {
			t.Errorf("Invalid URL. Wanted: %v, got: %v\n", c.ExpectedURL, actual)
		}
	}
}

func TestQR(t *testing.T) {

	for _, c := range cases {
		totp := &TOTP{Secret: c.Secret, IsBase32Secret: c.IsBase32Secret, Length: c.Digits}
		totp.Get()

		expected, _ := ioutil.ReadFile(c.ExpectedQR)

		actual, err := totp.QR(c.Label, c.Issuer)

		//ioutil.WriteFile(c.ExpectedQR, actual, 0644) // only use this when generating images for tests

		if err == nil {
			if bytes.Compare(actual, expected) != 0 {
				t.Error("Invalid QR.")
			}
			if c.QRError != nil {
				t.Fail()
			}
		} else {
			if err != c.QRError {
				t.Errorf("Expected an error. Wanted: %v, got: %v\n", c.QRError, err)
			}
		}
	}
}
