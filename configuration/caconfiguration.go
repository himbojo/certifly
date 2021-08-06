package caconfiguration

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"math/big"
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
	certificate x509.Certificate
	KeyLength   int
	KeyCurve    elliptic.Curve
}

// SetSerialNumber sets the serial number of the certificate
func (e *Init) SetSerialNumber() error {
	num, _ := new(big.Int).SetString("9999999999999999999999999999999999999999999999999999", 10)
	serial, err := rand.Int(rand.Reader, num)
	if err != nil {
		return fmt.Errorf("SetSerialNumber: Serial Number could not be set; %v", err)
	}
	e.certificate.SerialNumber = serial
	return nil
}

// GetSignatureAlgorithms returns an array of Signature Algorithms
func (e *Init) GetSignatureAlgorithms() []x509.SignatureAlgorithm {
	signatureAlgorithmChoices := []x509.SignatureAlgorithm{x509.SHA256WithRSA, x509.SHA384WithRSA, x509.SHA512WithRSA, x509.ECDSAWithSHA256, x509.ECDSAWithSHA384, x509.ECDSAWithSHA512}
	return signatureAlgorithmChoices
}

// GetPublicKeyAlgorithms returns an array of Public Key Algorithms
func (e *Init) GetPublicKeyAlgorithms() []x509.PublicKeyAlgorithm {

	publicKeyAlgorithmChoices := []x509.PublicKeyAlgorithm{x509.RSA, x509.ECDSA}
	return publicKeyAlgorithmChoices
}

// SetSignatureAlgorithm sets the signature algorithm of the certificate
func (e *Init) SetSignatureAlgorithm(choice int) error {
	choices := e.GetSignatureAlgorithms()
	var signatureAlgorithm x509.SignatureAlgorithm

	if choice <= len(choices) {
		signatureAlgorithm = choices[choice]
		e.certificate.SignatureAlgorithm = signatureAlgorithm
	} else {
		return fmt.Errorf("SetSignatureAlgorithm: Choice is invalid")
	}
	return nil
}

// SetPublicKeyAlgorithm sets the signature algorithm of the certificate
func (e *Init) SetPublicKeyAlgorithm(choice int) error {
	choices := e.GetPublicKeyAlgorithms()
	var publicKeyAlgorithm x509.PublicKeyAlgorithm

	if choice <= len(choices) {
		publicKeyAlgorithm = choices[choice]
		e.certificate.PublicKeyAlgorithm = publicKeyAlgorithm
	} else {
		return fmt.Errorf("SetPublicKeyAlgorithm: Choice is invalid")
	}
	return nil
}

// SetSubjectCommonName sets the common name of the certificate subject
func (e *Init) SetSubjectCommonName(name string) error {
	if name != "" {
		e.certificate.Subject.CommonName = name
	} else {
		return fmt.Errorf("SetSubjectCommonName: No Subject Common Name was set")
	}
	return nil
}

// SetNotAfter sets the not after date on the certificate
func (e *Init) SetNotAfter(years, months, days int) {
	e.certificate.NotAfter = time.Now().AddDate(years, months, days)
}

// SetDefaultCAKeyUsages sets the default key usages for a CA
func (e *Init) SetDefaultCAKeyUsages() {
	e.certificate.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign
}

// SetNotBefore sets the default not before time (now)
func (e *Init) SetNotBefore() {
	e.certificate.NotBefore = time.Now()
}

// SetPathLengthConstraint sets the path length constraint of the certificate
func (e *Init) SetPathLengthConstraint(pathLengthConstraint int) {
	if pathLengthConstraint == 0 {
		e.certificate.MaxPathLenZero = true
	}
	e.certificate.MaxPathLen = pathLengthConstraint
}

// SetCA sets whether it is going to be a CA or not
func (e *Init) SetCA() {
	e.certificate.IsCA = true
}

// SetBasicConstraintsValid sets where the basic contrains are valid
func (e *Init) SetBasicConstraintsValid() {
	e.certificate.BasicConstraintsValid = true
}

// GetKeyLengths returns a list of available key lengths
func (e *Init) GetKeyLengths() ([]int, error) {
	if e.certificate.PublicKeyAlgorithm == x509.RSA {
		return []int{1024, 2048, 4096, 8192, 16384}, nil
	} else if e.certificate.PublicKeyAlgorithm == x509.ECDSA {
		return []int{256, 384, 521}, nil
	} else {
		return nil, fmt.Errorf("GetKeyLengths: Public Key Algorithm has not been set")
	}
}

// SetKeyLength sets the key length
func (e *Init) SetKeyLength(choice int) error {
	keyLengths, err := e.GetKeyLengths()
	if e.certificate.PublicKeyAlgorithm == x509.RSA {
		e.KeyLength = keyLengths[choice]
	} else if e.certificate.PublicKeyAlgorithm == x509.ECDSA {
		switch choice {
		case 0:
			e.KeyCurve = elliptic.P256()
		case 1:
			e.KeyCurve = elliptic.P384()
		case 2:
			e.KeyCurve = elliptic.P521()
		}
	} else {
		return fmt.Errorf("GetKeyLengths: Public Key Algorithm has not been set; %v", err)
	}
	return nil
}

// SetCountry sets the country attribute of the certificate request
func (e *Init) SetCountry(c []string) {
	e.certificate.Subject.Country = c
}

// SetOrganisation sets the Organization attribute of the certificate request
func (e *Init) SetOrganisation(c []string) {
	e.certificate.Subject.Organization = c
}

// SetOrganisationalUnit sets the OrganizationalUnit attribute of the certificate request
func (e *Init) SetOrganisationalUnit(c []string) {
	e.certificate.Subject.OrganizationalUnit = c
}

// SetLocality sets the Locality attribute of the certificate request
func (e *Init) SetLocality(c []string) {
	e.certificate.Subject.Locality = c
}

// SetProvince sets the Province attribute of the certificate request
func (e *Init) SetProvince(c []string) {
	e.certificate.Subject.Province = c
}

// SetStreetAddress sets the StreetAddress attribute of the certificate request
func (e *Init) SetStreetAddress(c []string) {
	e.certificate.Subject.StreetAddress = c
}

// SetPostalCodes sets the PostalCode attribute of the certificate request
func (e *Init) SetPostalCodes(c []string) {
	e.certificate.Subject.PostalCode = c
}

// GetCertificateRequest returns the current certificate request
func (e *Init) GetCertificateRequest() x509.Certificate {
	return e.certificate
}
