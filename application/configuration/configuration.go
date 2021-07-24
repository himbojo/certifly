package configuration

import (
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"math/big"
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
