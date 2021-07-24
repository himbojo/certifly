package configuration

import "fmt"

// TODO:
// ROOT CA OR SUB CA
// CREATE NEW PRIVATE KEY, OR CHOOSE ONE TO USE
// CRYPTOGRAPHIC PROVIDER, E.G. RSA#MICROSOFT KEY STORAGE PROVIDER
// KEY LENGTH E.G. 4096
// HASH ALGORITHM E.G. SHA256
// ENTER CN AND THEN DN SUFFIX
// VALIDITY PERIOD OF CA, YEARS, MONTHS, DAYS
// OPPORTUNITY TO ADD INF WITH CERTIFICATE POLICIES AND OTHER VALUES TO OVERRIDE, e.g. adding non-repudiation to defaults: Digital Signature, Certificate Signing, Off-line CRL Signing, CRL Signing (c6)
// PRINTS CERTIFICATE DETAILS AND RETURNS DATABASE AND CERT LOCATION

// Init configuration of a certificate authority
type Init struct {
	commonName            string
	dnSuffix              string
	caType                int
	privateKey            int
	cryptographicProvider int
	keyLength             int
	hashAlgorithm         int
	validityPeriod        int
	useINF                int
}

// SetCACommonName sets and returns a ca name
func (e *Init) SetCACommonName() {
	var commonName string
	fmt.Scanln(&commonName)
	e.commonName = commonName
}

// GetCACommonName returns a CA Name
func (e *Init) GetCACommonName() string {
	return e.commonName
}
