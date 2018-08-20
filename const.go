package otp

// Default settings for all generators
const (
	DefaultLength = 6  // Default length of the generated tokens
	DefaultPeriod = 30 // Default time period for TOTP tokens, in seconds

	// This used to be 100, and here's why I changed it to 20. The HOTP spec recommends
	// the secret be 160 bits. 2^160 = (2^5)^32 = 32^32. Note that the two bases we
	// have are base 62 (for alphanum mixed case) and base32 (which Google prefers).
	// Setting the secret to 20 genererates a length 32 base 32 secret. We avoid gigantic
	// QR codes, and have sufficient entropy that's not greater than the number of atoms in
	// the universe. <3
	DefaultRandomSecretLength = 20 // Default random secret length

	DefaultWindowBack    = 1 // Default TOTP verification window back steps
	DefaultWindowForward = 1 // Default TOTP verification window forward steps
)

// Maximum values for all generators
const (
	MaxLength = 10 // Maximum token length
)
