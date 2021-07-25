package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"go-ca/application/configuration"
	"io/ioutil"
	"log"
	"os"
)

// CreateSelfSignedCertificate creates a self signed certificate and returns the certificate in bytes
func CreateSelfSignedCertificate(caConfiguration configuration.Init) (certBytes []byte, err error) {
	if caConfiguration.Certificate.PublicKeyAlgorithm == x509.RSA {
		priv, err := rsa.GenerateKey(rand.Reader, caConfiguration.KeyLength)
		certBytes, err = x509.CreateCertificate(rand.Reader, &caConfiguration.Certificate, &caConfiguration.Certificate, &priv.PublicKey, priv)
		if err != nil {
			return nil, fmt.Errorf("CreateSelfSignedCertificate: RSA Public Key Algorithm has not been set")
		}
		return certBytes, nil
	} else if caConfiguration.Certificate.PublicKeyAlgorithm == x509.ECDSA {
		priv, err := ecdsa.GenerateKey(caConfiguration.KeyCurve, rand.Reader)
		certBytes, err = x509.CreateCertificate(rand.Reader, &caConfiguration.Certificate, &caConfiguration.Certificate, &priv.PublicKey, priv)
		if err != nil {
			return nil, fmt.Errorf("CreateSelfSignedCertificate: ECDSA Public Key Algorithm has not been set")
		}
		return certBytes, nil
	} else {
		return nil, fmt.Errorf("CreateSelfSignedCertificate: Public Key Algorithm has not been set")
	}
}

func main() {
	caConfiguration := configuration.Init{}

	err := caConfiguration.SetSerialNumber()
	if err != nil {
		log.Fatal(err)
	}

	signatureAlgorithmChoices := caConfiguration.GetSignatureAlgorithmChoices()
	fmt.Println("Choose Signature Algorithm: ")
	for _, sigAlg := range signatureAlgorithmChoices {
		fmt.Printf("%v. %v\n", sigAlg.Choice, sigAlg.SigAlg.String())
	}
	var signatureAlgorithmChoice int
	fmt.Scanln(&signatureAlgorithmChoice)
	err = caConfiguration.SetSignatureAlgorithm(signatureAlgorithmChoice)
	if err != nil {
		log.Fatal(err)
	}

	publicKeyAlgorithmChoices := caConfiguration.GetPublicKeyAlgorithmChoices()
	fmt.Println("Choose Public Key Algorithm: ")
	for _, pkAlg := range publicKeyAlgorithmChoices {
		fmt.Printf("%v. %v\n", pkAlg.Choice, pkAlg.PkAlg.String())
	}
	var publicKeyAlgorithmChoice int
	fmt.Scanln(&publicKeyAlgorithmChoice)
	err = caConfiguration.SetPublicKeyAlgorithm(publicKeyAlgorithmChoice)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Enter Common Name: ")
	var commonName string
	fmt.Scanln(&commonName)
	err = caConfiguration.SetSubjectCommonName(commonName)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Enter Country (Separated by commas): ")
	var countryCS string
	fmt.Scanln(&countryCS)
	caConfiguration.SetSubjectCountries(countryCS)

	fmt.Println("Enter Organization (Separated by commas): ")
	var organizationCS string
	fmt.Scanln(&organizationCS)
	caConfiguration.SetSubjectOrganizations(organizationCS)

	fmt.Println("Enter Organizational Unit (Separated by commas): ")
	var organizationalUnitCS string
	fmt.Scanln(&organizationalUnitCS)
	caConfiguration.SetSubjectOrganizationalUnits(organizationalUnitCS)

	fmt.Println("Enter Locality (Separated by commas): ")
	var localityCS string
	fmt.Scanln(&localityCS)
	caConfiguration.SetSubjectLocalities(localityCS)

	fmt.Println("Enter Province (Separated by commas): ")
	var provinceCS string
	fmt.Scanln(&provinceCS)
	caConfiguration.SetSubjectProvinces(provinceCS)

	fmt.Println("Enter Street Address (Separated by commas): ")
	var streetAddressCS string
	fmt.Scanln(&streetAddressCS)
	caConfiguration.SetSubjectStreetAddresses(streetAddressCS)

	fmt.Println("Enter Postal Code (Separated by commas): ")
	var postalCodeCS string
	fmt.Scanln(&postalCodeCS)
	caConfiguration.SetSubjectPostalCodes(postalCodeCS)

	caConfiguration.SetNotBefore()
	years := 0
	months := 0
	days := 0

	fmt.Println("Enter Validity Period Years:")
	fmt.Scanln(&years)
	fmt.Println("Enter Validity Period Months:")
	fmt.Scanln(&months)
	fmt.Println("Enter Validity Period Days:")
	fmt.Scanln(&days)
	caConfiguration.SetNotAfter(years, months, days)

	fmt.Println("Enter Path Length Constraint for CA (Enter -1 for no constraint): ")
	pathLengthConstraint := 0
	fmt.Scanln(&pathLengthConstraint)
	caConfiguration.SetPathLengthConstraint(pathLengthConstraint)

	caConfiguration.SetDefaultCAKeyUsages()
	caConfiguration.SetCA()
	caConfiguration.SetBasicConstraintsValid()

	var newCertBytes []byte
	var keyLengthChoice int

	fmt.Println("Choose the Key Length: ")
	keyLengths, err := caConfiguration.GetKeyLengths()
	for i, keyLength := range keyLengths {
		fmt.Printf("%v. %v\n", i+1, keyLength)
	}
	fmt.Scanln(&keyLengthChoice)
	caConfiguration.SetKeyLength(keyLengthChoice)

	newCertBytes, err = CreateSelfSignedCertificate(caConfiguration)
	if err != nil {
		log.Fatal(err)
	}

	//cert, err := x509.ParseCertificate(newCertBytes)
	b := pem.Block{Type: "CERTIFICATE", Bytes: newCertBytes}
	certPEM := pem.EncodeToMemory(&b)
	ioutil.WriteFile("/mnt/c/temp/test.crt", certPEM, os.ModePerm)
}
