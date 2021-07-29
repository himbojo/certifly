package configuration

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"math/big"
	"strings"
	"time"
)

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
	Certificate x509.Certificate
	KeyLength   int
	KeyCurve    elliptic.Curve
}

// SignatureAlgorithmChoice is an object with a choice and signature algorithm
type SignatureAlgorithmChoice struct {
	Choice int
	SigAlg x509.SignatureAlgorithm
}

// PublicKeyAlgorithmChoice is an object with a choice and public key algorithm
type PublicKeyAlgorithmChoice struct {
	Choice int
	PkAlg  x509.PublicKeyAlgorithm
}

// SetSerialNumber sets the serial number of the certificate
func (e *Init) SetSerialNumber() error {
	num, _ := new(big.Int).SetString("9999999999999999999999999999999999999999999999999999", 10)
	serial, err := rand.Int(rand.Reader, num)
	if err != nil {
		return fmt.Errorf("SetSerialNumber: Serial Number could not be set; %v", err)
	}
	e.Certificate.SerialNumber = serial
	return nil
}

// GetSignatureAlgorithmChoices returns an array of Signature Algorithm Choices
func (e *Init) GetSignatureAlgorithmChoices() []SignatureAlgorithmChoice {
	SHA256RSA := SignatureAlgorithmChoice{Choice: 1, SigAlg: x509.SHA256WithRSA}
	SHA384RSA := SignatureAlgorithmChoice{Choice: 2, SigAlg: x509.SHA384WithRSA}
	SHA512RSA := SignatureAlgorithmChoice{Choice: 3, SigAlg: x509.SHA512WithRSA}
	SHA256ECDSA := SignatureAlgorithmChoice{Choice: 4, SigAlg: x509.ECDSAWithSHA256}
	SHA384ECDSA := SignatureAlgorithmChoice{Choice: 5, SigAlg: x509.ECDSAWithSHA384}
	SHA512ECDSA := SignatureAlgorithmChoice{Choice: 6, SigAlg: x509.ECDSAWithSHA512}

	signatureAlgorithmChoices := []SignatureAlgorithmChoice{SHA256RSA, SHA384RSA, SHA512RSA, SHA256ECDSA, SHA384ECDSA, SHA512ECDSA}
	return signatureAlgorithmChoices
}

// GetPublicKeyAlgorithmChoices returns an array of Public Key Algorithm Choices
func (e *Init) GetPublicKeyAlgorithmChoices() []PublicKeyAlgorithmChoice {
	RSA := PublicKeyAlgorithmChoice{Choice: 1, PkAlg: x509.RSA}
	ECDSA := PublicKeyAlgorithmChoice{Choice: 2, PkAlg: x509.ECDSA}

	publicKeyAlgorithmChoices := []PublicKeyAlgorithmChoice{RSA, ECDSA}
	return publicKeyAlgorithmChoices
}

// SetSignatureAlgorithm sets the signature algorithm of the certificate
func (e *Init) SetSignatureAlgorithm(choice int) error {
	choices := e.GetSignatureAlgorithmChoices()
	var signatureAlgorithm x509.SignatureAlgorithm

	if choice >= 1 && choice <= len(choices) {
		signatureAlgorithm = choices[choice-1].SigAlg
		e.Certificate.SignatureAlgorithm = signatureAlgorithm
	} else {
		return fmt.Errorf("SetSignatureAlgorithm: Choice is invalid")
	}
	return nil
}

// SetPublicKeyAlgorithm sets the signature algorithm of the certificate
func (e *Init) SetPublicKeyAlgorithm(choice int) error {
	choices := e.GetPublicKeyAlgorithmChoices()
	var publicKeyAlgorithm x509.PublicKeyAlgorithm

	if choice >= 1 && choice <= len(choices) {
		publicKeyAlgorithm = choices[choice-1].PkAlg
		e.Certificate.PublicKeyAlgorithm = publicKeyAlgorithm
	} else {
		return fmt.Errorf("SetPublicKeyAlgorithm: Choice is invalid")
	}
	return nil
}

// SetSubjectCommonName sets the common name of the certificate subject
func (e *Init) SetSubjectCommonName(name string) error {
	if name != "" {
		e.Certificate.Subject.CommonName = name
	} else {
		return fmt.Errorf("SetSubjectCommonName: No Subject Common Name was set")
	}
	return nil
}

// SetSubjectCountries sets the countries of the certificate
func (e *Init) SetSubjectCountries(countries string) {
	if countries != "" {
		e.Certificate.Subject.Country = strings.Split(countries, ",")
	}
}

// SetSubjectOrganizations sets the organizations of the certificate
func (e *Init) SetSubjectOrganizations(organizations string) {
	if organizations != "" {
		e.Certificate.Subject.Organization = strings.Split(organizations, ",")
	}
}

// SetSubjectOrganizationalUnits sets the organizatinal units of the certificate
func (e *Init) SetSubjectOrganizationalUnits(organizationalUnits string) {
	if organizationalUnits != "" {
		e.Certificate.Subject.OrganizationalUnit = strings.Split(organizationalUnits, ",")
	}
}

// SetSubjectLocalities sets the localities of the certificate
func (e *Init) SetSubjectLocalities(localities string) {
	if localities != "" {
		e.Certificate.Subject.Locality = strings.Split(localities, ",")
	}
}

// SetSubjectProvinces sets the provinces of the certificate
func (e *Init) SetSubjectProvinces(provinces string) {
	if provinces != "" {
		e.Certificate.Subject.Province = strings.Split(provinces, ",")
	}
}

// SetSubjectStreetAddresses sets the street addresses of the certificate
func (e *Init) SetSubjectStreetAddresses(streetAddresses string) {
	if streetAddresses != "" {
		e.Certificate.Subject.StreetAddress = strings.Split(streetAddresses, ",")
	}
}

// SetSubjectPostalCodes sets the postal codes of the certificate
func (e *Init) SetSubjectPostalCodes(postalCodes string) {
	if postalCodes != "" {
		e.Certificate.Subject.PostalCode = strings.Split(postalCodes, ",")
	}
}

// SetNotAfter sets the not after date on the certificate
func (e *Init) SetNotAfter(years, months, days int) {
	e.Certificate.NotAfter = time.Now().AddDate(years, months, days)
}

// SetDefaultCAKeyUsages sets the default key usages for a CA
func (e *Init) SetDefaultCAKeyUsages() {
	e.Certificate.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign
}

// SetNotBefore sets the default not before time (now)
func (e *Init) SetNotBefore() {
	e.Certificate.NotBefore = time.Now()
}

// SetPathLengthConstraint sets the path length constraint of the certificate
func (e *Init) SetPathLengthConstraint(pathLengthConstraint int) {
	if pathLengthConstraint == 0 {
		e.Certificate.MaxPathLenZero = true
	}
	e.Certificate.MaxPathLen = pathLengthConstraint
}

// SetCA sets whether it is going to be a CA or not
func (e *Init) SetCA() {
	e.Certificate.IsCA = true
}

// SetBasicConstraintsValid sets where the basic contrains are valid
func (e *Init) SetBasicConstraintsValid() {
	e.Certificate.BasicConstraintsValid = true
}

// GetKeyLengths returns a list of available key lengths
func (e *Init) GetKeyLengths() ([]int, error) {
	if e.Certificate.PublicKeyAlgorithm == x509.RSA {
		return []int{1024, 2048, 4096, 8192, 16384}, nil
	} else if e.Certificate.PublicKeyAlgorithm == x509.ECDSA {
		return []int{256, 384, 521}, nil
	} else {
		return nil, fmt.Errorf("GetKeyLengths: Public Key Algorithm has not been set")
	}
}

// SetKeyLength sets the key length
func (e *Init) SetKeyLength(choice int) error {
	keyLengths, err := e.GetKeyLengths()
	if e.Certificate.PublicKeyAlgorithm == x509.RSA {
		e.KeyLength = keyLengths[choice-1]
	} else if e.Certificate.PublicKeyAlgorithm == x509.ECDSA {
		switch choice {
		case 1:
			e.KeyCurve = elliptic.P256()
		case 2:
			e.KeyCurve = elliptic.P384()
		case 3:
			e.KeyCurve = elliptic.P521()
		}
	} else {
		return fmt.Errorf("GetKeyLengths: Public Key Algorithm has not been set; %v", err)
	}
	return nil
}
