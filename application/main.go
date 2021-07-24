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
	"io/ioutil"
	"math/big"
	"os"
	"strconv"
	"strings"
	"time"
)

func main() {
	fmt.Println("hello, world")

	num, _ := new(big.Int).SetString("9999999999999999999999999999999999999999999999999999", 10)
	serial, err := rand.Int(rand.Reader, num)
	_ = err

	fmt.Println("Choose Signature Algorithm: ")
	fmt.Printf("1. %v\n2. %v\n3. %v\n4. %v\n5. %v\n6. %v\n", x509.SHA256WithRSA.String(), x509.SHA384WithRSA.String(), x509.SHA512WithRSA.String(), x509.ECDSAWithSHA256.String(), x509.ECDSAWithSHA384.String(), x509.ECDSAWithSHA512.String())
	var signatureAlgorithmChoice int
	var signatureAlgorithm x509.SignatureAlgorithm
	fmt.Scanln(&signatureAlgorithmChoice)
	switch signatureAlgorithmChoice {
	case 1:
		signatureAlgorithm = x509.SHA256WithRSA
	case 2:
		signatureAlgorithm = x509.SHA384WithRSA
	case 3:
		signatureAlgorithm = x509.SHA512WithRSA
	case 4:
		signatureAlgorithm = x509.ECDSAWithSHA256
	case 5:
		signatureAlgorithm = x509.ECDSAWithSHA384
	case 6:
		signatureAlgorithm = x509.ECDSAWithSHA512
	default:
		err := fmt.Errorf("Please select a valid Signature Algorithm")
		fmt.Println(err.Error())
		os.Exit(1)
	}

	fmt.Println("Choose Public Key Algorithm: ")
	fmt.Printf("1. %v\n2. %v\n", x509.RSA.String(), x509.ECDSA.String())
	var publicKeyAlgorithmChoice int
	var publicKeyAlgorithm x509.PublicKeyAlgorithm
	fmt.Scanln(&publicKeyAlgorithmChoice)
	switch publicKeyAlgorithmChoice {
	case 1:
		publicKeyAlgorithm = x509.RSA
	case 2:
		publicKeyAlgorithm = x509.ECDSA
	default:
		err := fmt.Errorf("Please select a valid Public Key Algorithm")
		fmt.Println(err.Error())
		os.Exit(1)
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
		SerialNumber:          serial,
		SignatureAlgorithm:    signatureAlgorithm,
		PublicKeyAlgorithm:    publicKeyAlgorithm,
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
	if publicKeyAlgorithm == x509.RSA {
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

	if publicKeyAlgorithm == x509.ECDSA {
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
