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

// CreateSignedCertificate creates a CA signed certificate and returns the certificate components
func CreateSignedCertificate(caConfiguration configuration.Init, parentPub x509.Certificate, parentPriv interface{}) (certBytes []byte, privateKey []byte, err error) {
	if caConfiguration.Certificate.PublicKeyAlgorithm == x509.RSA {
		priv, err := rsa.GenerateKey(rand.Reader, caConfiguration.KeyLength)
		if err != nil {
			return nil, nil, fmt.Errorf("CreateCASignedCertificate: RSA Key couldn't be generated; %v", err)
		}
		if parentPriv == nil {
			parentPriv = priv
		}
		certBytes, err := x509.CreateCertificate(rand.Reader, &caConfiguration.Certificate, &parentPub, &priv.PublicKey, parentPriv)
		if err != nil {
			return nil, nil, fmt.Errorf("CreateCASignedCertificate: RSA Certificate couldn't be created; %v", err)
		}
		privateKey, err := x509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			return nil, nil, fmt.Errorf("CreateCASignedCertificate: RSA Private Key couldn't be marshaled; %v", err)
		}
		return certBytes, privateKey, nil
	} else if caConfiguration.Certificate.PublicKeyAlgorithm == x509.ECDSA {
		priv, err := ecdsa.GenerateKey(caConfiguration.KeyCurve, rand.Reader)
		if parentPriv == nil {
			parentPriv = priv
		}
		certBytes, err = x509.CreateCertificate(rand.Reader, &caConfiguration.Certificate, &parentPub, &priv.PublicKey, parentPriv)
		if err != nil {
			return nil, nil, fmt.Errorf("CreateCASignedCertificate: ECDSA Key couldn't be generated; %v", err)
		}
		privateKey, err := x509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			return nil, nil, fmt.Errorf("CreateCASignedCertificate: ECDSA Certificate couldn't be created; %v", err)
		}
		return certBytes, privateKey, nil
	} else {
		return nil, nil, fmt.Errorf("CreateCASignedCertificate: Public Key Algorithm has not been set")
	}
}

// CreateCAConfiguration asks for user input and returns a CA configuration
func CreateCAConfiguration() (configuration.Init, error) {
	caConfiguration := configuration.Init{}

	err := caConfiguration.SetSerialNumber()
	if err != nil {
		return caConfiguration, err
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
		return caConfiguration, err
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
		return caConfiguration, err
	}

	fmt.Println("Enter Common Name: ")
	var commonName string
	fmt.Scanln(&commonName)
	err = caConfiguration.SetSubjectCommonName(commonName)
	if err != nil {
		return caConfiguration, err
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
	if err != nil {
		return caConfiguration, err
	}
	fmt.Println("Enter Path Length Constraint for CA (Enter -1 for no constraint): ")
	pathLengthConstraint := 0
	fmt.Scanln(&pathLengthConstraint)
	caConfiguration.SetPathLengthConstraint(pathLengthConstraint)

	caConfiguration.SetDefaultCAKeyUsages()
	caConfiguration.SetCA()
	caConfiguration.SetBasicConstraintsValid()

	var keyLengthChoice int

	fmt.Println("Choose the Key Length: ")
	keyLengths, err := caConfiguration.GetKeyLengths()
	for i, keyLength := range keyLengths {
		fmt.Printf("%v. %v\n", i+1, keyLength)
	}
	fmt.Scanln(&keyLengthChoice)
	caConfiguration.SetKeyLength(keyLengthChoice)

	return caConfiguration, nil
}

// CreateRootCACertificate this creates a root CA certificate and return the public and private key
func CreateRootCACertificate(rootConfig configuration.Init) ([]byte, []byte, error) {
	newCertBytes, privateKey, err := CreateSignedCertificate(rootConfig, rootConfig.Certificate, nil)
	if err != nil {
		return nil, nil, err
	}
	return newCertBytes, privateKey, nil
}

// CreateSubCACertificate this creates a CA certificate and return the public and private key
func CreateSubCACertificate(subCAConfig configuration.Init, parentCert x509.Certificate, parentKey interface{}) ([]byte, []byte, error) {
	newCertBytes, privateKey, err := CreateSignedCertificate(subCAConfig, parentCert, parentKey)
	if err != nil {
		return nil, nil, err
	}
	return newCertBytes, privateKey, nil
}

func main() {
	rootConfig, err := CreateCAConfiguration()
	if err != nil {
		log.Fatal(err)
	}
	rootPubKey, rootPrivKey, err := CreateRootCACertificate(rootConfig)
	if err != nil {
		log.Fatal(err)
	}

	subCAConfig, err := CreateCAConfiguration()
	if err != nil {
		log.Fatal(err)
	}

	parentPriv, err := x509.ParsePKCS8PrivateKey(rootPrivKey)
	if err != nil {
		log.Fatal(err)
	}
	subCAPubKey, subCAPrivKey, err := CreateSubCACertificate(subCAConfig, rootConfig.Certificate, parentPriv)
	if err != nil {
		log.Fatal(err)
	}

	rootPubPem := pem.Block{Type: "CERTIFICATE", Bytes: rootPubKey}
	rootPubBytes := pem.EncodeToMemory(&rootPubPem)
	rootPrivPem := pem.Block{Type: "PRIVATE KEY", Bytes: rootPrivKey}
	rootPrivBytes := pem.EncodeToMemory(&rootPrivPem)
	ioutil.WriteFile("/mnt/c/temp/root/root.crt", rootPubBytes, os.ModePerm)
	ioutil.WriteFile("/mnt/c/temp/root/root.key", rootPrivBytes, os.ModePerm)

	subCAPubPem := pem.Block{Type: "CERTIFICATE", Bytes: subCAPubKey}
	subCAPubBytes := pem.EncodeToMemory(&subCAPubPem)
	subCAPrivPem := pem.Block{Type: "PRIVATE KEY", Bytes: subCAPrivKey}
	subCAPrivBytes := pem.EncodeToMemory(&subCAPrivPem)
	ioutil.WriteFile("/mnt/c/temp/subca/subca.crt", subCAPubBytes, os.ModePerm)
	ioutil.WriteFile("/mnt/c/temp/subca/subca.key", subCAPrivBytes, os.ModePerm)
}
