package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"go-ca/application/configuration"
	"io/ioutil"
	"log"
	"os"
	"strconv"
	"strings"
	"time"
)

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

	fmt.Println("Enter Country (Separated by commas): ")
	var countryCS string
	fmt.Scanln(&countryCS)
	country := strings.Split(countryCS, ",")

	fmt.Println("Enter Organization (Separated by commas): ")
	var organizationCS string
	fmt.Scanln(&organizationCS)
	organization := strings.Split(organizationCS, ",")

	fmt.Println("Enter Organizational Unit (Separated by commas): ")
	var organizationalUnitCS string
	fmt.Scanln(&organizationalUnitCS)
	organizationalUnit := strings.Split(organizationalUnitCS, ",")

	fmt.Println("Enter Locality (Separated by commas): ")
	var localityCS string
	fmt.Scanln(&localityCS)
	locality := strings.Split(localityCS, ",")

	fmt.Println("Enter Province (Separated by commas): ")
	var provinceCS string
	fmt.Scanln(&provinceCS)
	province := strings.Split(provinceCS, ",")

	fmt.Println("Enter Street Address (Separated by commas): ")
	var streetAddressCS string
	fmt.Scanln(&streetAddressCS)
	streetAddress := strings.Split(streetAddressCS, ",")

	fmt.Println("Enter Postal Code (Separated by commas): ")
	var postalCodeCS string
	fmt.Scanln(&postalCodeCS)
	postalCode := strings.Split(postalCodeCS, ",")

	var subject pkix.Name
	if commonName != "" {
		subject.CommonName = commonName
	}

	if country[0] != "" {
		subject.Country = country
	}

	if organization[0] != "" {
		subject.Organization = organization
	}

	if organizationalUnit[0] != "" {
		subject.OrganizationalUnit = organizationalUnit
	}

	if locality[0] != "" {
		subject.Locality = locality
	}

	if province[0] != "" {
		subject.Province = province
	}

	if streetAddress[0] != "" {
		subject.StreetAddress = streetAddress
	}

	if postalCode[0] != "" {
		subject.PostalCode = postalCode
	}

	fmt.Println("Enter Validity Period in Years, Months and Days (separated by commas e.g. 5,6,15)")
	var notAfterCS string
	fmt.Scanln(&notAfterCS)
	validityPeriodArray := strings.Split(notAfterCS, ",")
	years := 0
	months := 0
	days := 0

	switch len(validityPeriodArray) {
	case 3:
		years, err = strconv.Atoi(validityPeriodArray[0])
		months, err = strconv.Atoi(validityPeriodArray[1])
		days, err = strconv.Atoi(validityPeriodArray[2])
	case 2:
		years, err = strconv.Atoi(validityPeriodArray[0])
		months, err = strconv.Atoi(validityPeriodArray[1])
	case 1:
		years, err = strconv.Atoi(validityPeriodArray[0])
	}
	_ = err

	fmt.Println("Enter Path Length Constraint for CA (Enter -1 for no constraint): ")
	var pathLengthConstraintS string
	fmt.Scanln(&pathLengthConstraintS)
	pathLengthConstraint, err := strconv.Atoi(pathLengthConstraintS)

	certReqCA := x509.Certificate{
		SerialNumber:          caConfiguration.Certificate.SerialNumber,
		SignatureAlgorithm:    caConfiguration.Certificate.SignatureAlgorithm,
		PublicKeyAlgorithm:    caConfiguration.Certificate.PublicKeyAlgorithm,
		Subject:               subject,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(years, months, days),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            pathLengthConstraint,
	}
	if pathLengthConstraint == 0 {
		certReqCA.MaxPathLenZero = true
	}

	// rsa 1024, 2048, 4096, 8192, 16384
	// ecdsa 256, 384, 521
	var newCertBytes []byte
	var keyLengthChoice int

	fmt.Println("Choose the Key Length: ")
	if caConfiguration.Certificate.PublicKeyAlgorithm == x509.RSA {
		fmt.Printf("1. %v\n3. %v\n3. %v\n4. %v\n5. %v\n", "1024", "2048", "4096", "8192", "16384")
		fmt.Scanln(&keyLengthChoice)
		var keyLength int
		switch keyLengthChoice {
		case 1:
			keyLength = 1024
		case 2:
			keyLength = 2048
		case 3:
			keyLength = 4096
		case 5:
			keyLength = 8192
		case 6:
			keyLength = 16384
		default:
			err := fmt.Errorf("Please select a valid Key Length")
			fmt.Println(err.Error())
			os.Exit(1)
		}
		priv, err := rsa.GenerateKey(rand.Reader, keyLength)
		newCertBytes, err = x509.CreateCertificate(rand.Reader, &certReqCA, &certReqCA, &priv.PublicKey, priv)
		_ = err
	}

	if caConfiguration.Certificate.PublicKeyAlgorithm == x509.ECDSA {
		fmt.Printf("1. %v\n3. %v\n3. %v\n", "256", "384", "521")
		fmt.Scanln(&keyLengthChoice)
		var keyCurve elliptic.Curve
		switch keyLengthChoice {
		case 1:
			keyCurve = elliptic.P256()
		case 2:
			keyCurve = elliptic.P384()
		case 3:
			keyCurve = elliptic.P521()
		default:
			err := fmt.Errorf("Please select a valid Key Length")
			fmt.Println(err.Error())
			os.Exit(1)
		}
		priv, err := ecdsa.GenerateKey(keyCurve, rand.Reader)
		newCertBytes, err = x509.CreateCertificate(rand.Reader, &certReqCA, &certReqCA, &priv.PublicKey, priv)
		_ = err
	}

	//cert, err := x509.ParseCertificate(newCertBytes)
	b := pem.Block{Type: "CERTIFICATE", Bytes: newCertBytes}
	certPEM := pem.EncodeToMemory(&b)
	ioutil.WriteFile("/mnt/c/temp/test.crt", certPEM, os.ModePerm)
	//cert, err := x509.ParseCertificate(newCertBytes)
	_ = newCertBytes
	_ = err
}

// TODO: Domain join CA
