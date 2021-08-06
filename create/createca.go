package createca

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	request "certifly/certificate/request"
	"strconv"
	"strings"

	"github.com/manifoldco/promptui"
)

const (
	country            = "Country"
	organization       = "Organization"
	organizationalUnit = "Organizational Unit"
	locality           = "Locality"
	province           = "Province"
	streetAddress      = "Street Address"
	postalCode         = "PostalCode"
	exit               = "Exit"
)

// CreateSignedCertificate creates a CA signed certificate and returns the certificate components
func CreateSignedCertificate(caConfiguration request.Init, parentPub x509.Certificate, parentPriv interface{}) (certBytes []byte, privateKey []byte, err error) {
	request := caConfiguration.GetCertificateRequest()
	if request.PublicKeyAlgorithm == x509.RSA {
		priv, err := rsa.GenerateKey(rand.Reader, caConfiguration.KeyLength)
		if err != nil {
			return nil, nil, fmt.Errorf("CreateCASignedCertificate: RSA Key couldn't be generated; %v", err)
		}
		if parentPriv == nil {
			parentPriv = priv
		}
		certBytes, err := x509.CreateCertificate(rand.Reader, &request, &parentPub, &priv.PublicKey, parentPriv)
		if err != nil {
			return nil, nil, fmt.Errorf("CreateCASignedCertificate: RSA Certificate couldn't be created; %v", err)
		}
		privateKey, err := x509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			return nil, nil, fmt.Errorf("CreateCASignedCertificate: RSA Private Key couldn't be marshaled; %v", err)
		}
		return certBytes, privateKey, nil
	} else if request.PublicKeyAlgorithm == x509.ECDSA {
		priv, err := ecdsa.GenerateKey(caConfiguration.KeyCurve, rand.Reader)
		if parentPriv == nil {
			parentPriv = priv
		}
		certBytes, err = x509.CreateCertificate(rand.Reader, &request, &parentPub, &priv.PublicKey, parentPriv)
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

// LoopPrompt asks user to enter one or more values
func LoopPrompt(p string) ([]string, error) {
	var array []string
	for {
		prompt := promptui.Prompt{
			Label: fmt.Sprintf("Enter %v (Press Enter to Skip)", p),
		}
		entry, err := prompt.Run()
		if err != nil {
			return nil, err
		}
		if strings.TrimSpace(entry) == "" {
			break
		}
		array = append(array, entry)
	}
	return array, nil
}

// SinglePrompt asks the user to enter one value
func SinglePrompt(p string) (string, error) {
	prompt := promptui.Prompt{
		Label: fmt.Sprintf("Enter %v", p),
	}
	entry, err := prompt.Run()
	if err != nil {
		return "", err
	}
	return entry, nil
}

// Configuration asks for user input and returns a CA configuration
func Configuration() (request.Init, error) {
	caConfiguration := request.Init{}

	err := caConfiguration.SetSerialNumber()
	if err != nil {
		return caConfiguration, err
	}

	pubAlgs := caConfiguration.GetPublicKeyAlgorithms()
	template := &promptui.SelectTemplates{
		Active:   fmt.Sprintf("%v {{ .String | cyan }}", promptui.IconSelect),
		Inactive: "{{ .String }}",
		Selected: "{{ .String }}",
	}
	pubAlg := promptui.Select{
		Label:     "Select Public Key Algorithm",
		Items:     pubAlgs,
		Templates: template,
	}
	i, _, err := pubAlg.Run()
	if err != nil {
		return caConfiguration, err
	}
	err = caConfiguration.SetPublicKeyAlgorithm(i)
	if err != nil {
		return caConfiguration, err
	}

	keyLengths, err := caConfiguration.GetKeyLengths()
	template = &promptui.SelectTemplates{
		Active:   fmt.Sprintf("%v {{ . | cyan }}", promptui.IconSelect),
		Inactive: "{{ . }}",
		Selected: "{{ . }}",
	}
	keyLength := promptui.Select{
		Label:     "Select Key Length",
		Items:     keyLengths,
		Templates: template,
	}
	i, _, err = keyLength.Run()
	if err != nil {
		return caConfiguration, err
	}
	caConfiguration.SetKeyLength(i)

	sigAlgs := caConfiguration.GetSignatureAlgorithms()
	template = &promptui.SelectTemplates{
		Active:   fmt.Sprintf("%v {{ .String | cyan }}", promptui.IconSelect),
		Inactive: "{{ .String }}",
		Selected: "{{ .String }}",
	}
	sigAlg := promptui.Select{
		Label:     "Select Signature Algorithm",
		Items:     sigAlgs,
		Templates: template,
	}
	i, _, err = sigAlg.Run()
	if err != nil {
		return caConfiguration, err
	}
	//var signatureAlgorithmChoice int
	err = caConfiguration.SetSignatureAlgorithm(i)
	if err != nil {
		return caConfiguration, err
	}

	pathLengthConstraintPrompt := promptui.Prompt{
		Label: "Enter Path Length Constraint (-1 for None)",
	}
	pathLengthConstraint, err := pathLengthConstraintPrompt.Run()
	if err != nil {
		fmt.Printf("Prompt failed %v\n", err)
		return caConfiguration, err
	}
	plc, err := strconv.Atoi(pathLengthConstraint)
	if err != nil {
		return caConfiguration, err
	}
	caConfiguration.SetPathLengthConstraint(plc)

	years, err := SinglePrompt("Years")
	if err != nil {
		return caConfiguration, err
	}
	months, err := SinglePrompt("Months")
	if err != nil {
		return caConfiguration, err
	}
	days, err := SinglePrompt("Days")
	if err != nil {
		return caConfiguration, err
	}

	if years == "" {
		years = "0"
	}
	if months == "" {
		months = "0"
	}
	if days == "" {
		days = "0"
	}
	y, err := strconv.Atoi(years)
	m, err := strconv.Atoi(months)
	d, err := strconv.Atoi(days)
	if err != nil {
		return caConfiguration, err
	}
	caConfiguration.SetNotAfter(y, m, d)
	if err != nil {
		return caConfiguration, err
	}

	commonname, err := SinglePrompt("Common Name")
	if err != nil {
		return caConfiguration, err
	}
	err = caConfiguration.SetSubjectCommonName(commonname)
	if err != nil {
		return caConfiguration, err
	}

	options := []string{country, organization, organizationalUnit, locality, province, streetAddress, postalCode, exit}
	for {
		template := &promptui.SelectTemplates{
			Active:   fmt.Sprintf("%v {{ . | cyan }}", promptui.IconSelect),
			Inactive: "{{ . }}",
			Selected: "{{ . }}",
		}
		prompt := promptui.Select{
			Label:     "Options",
			Items:     options,
			Templates: template,
		}
		_, entry, err := prompt.Run()
		if err != nil {
			return caConfiguration, err
		}

		switch entry {
		case country:
			country, err := LoopPrompt("Countries")
			if err != nil {
				return caConfiguration, err
			}
			caConfiguration.SetCountry(country)
		case organization:
			organization, err := LoopPrompt("Organizations")
			if err != nil {
				return caConfiguration, err
			}
			caConfiguration.SetOrganisation(organization)
		case organizationalUnit:
			organizationalUnit, err := LoopPrompt("Organization Units")
			if err != nil {
				return caConfiguration, err
			}
			caConfiguration.SetOrganisationalUnit(organizationalUnit)
		case locality:
			locality, err := LoopPrompt("Locality")
			if err != nil {
				return caConfiguration, err
			}
			caConfiguration.SetLocality(locality)
		case province:
			province, err := LoopPrompt("Province")
			if err != nil {
				return caConfiguration, err
			}
			caConfiguration.SetProvince(province)
		case streetAddress:
			streetAddress, err := LoopPrompt("Street Address")
			if err != nil {
				return caConfiguration, err
			}
			caConfiguration.SetStreetAddress(streetAddress)
		case postalCode:
			postalCode, err := LoopPrompt("Postal Codes")
			if err != nil {
				return caConfiguration, err
			}
			caConfiguration.SetPostalCodes(postalCode)
		}
		if entry == exit {
			break
		}
	}

	caConfiguration.SetNotBefore()
	caConfiguration.SetDefaultCAKeyUsages()
	caConfiguration.SetCA()
	caConfiguration.SetBasicConstraintsValid()

	return caConfiguration, nil
}

// CreateRootCACertificate this creates a root CA certificate and return the public and private key
func CreateRootCACertificate(rootConfig request.Init) ([]byte, []byte, error) {
	newCertBytes, privateKey, err := CreateSignedCertificate(rootConfig, rootConfig.GetCertificateRequest(), nil)
	if err != nil {
		return nil, nil, err
	}
	return newCertBytes, privateKey, nil
}

// CreateSubCACertificate this creates a CA certificate and return the public and private key
func CreateSubCACertificate(subCAConfig request.Init, parentCert x509.Certificate, parentKey interface{}) ([]byte, []byte, error) {
	newCertBytes, privateKey, err := CreateSignedCertificate(subCAConfig, parentCert, parentKey)
	if err != nil {
		return nil, nil, err
	}
	return newCertBytes, privateKey, nil
}
