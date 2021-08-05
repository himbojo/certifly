package createca

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	caconfiguration "go-ca/configuration"
	"strconv"

	"github.com/manifoldco/promptui"
)

// CreateSignedCertificate creates a CA signed certificate and returns the certificate components
func CreateSignedCertificate(caConfiguration caconfiguration.Init, parentPub x509.Certificate, parentPriv interface{}) (certBytes []byte, privateKey []byte, err error) {
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

// Configuration asks for user input and returns a CA configuration
func Configuration() (caconfiguration.Init, error) {
	caConfiguration := caconfiguration.Init{}

	err := caConfiguration.SetSerialNumber()
	if err != nil {
		return caConfiguration, err
	}

	sigAlgs := caConfiguration.GetSignatureAlgorithms()
	template := &promptui.SelectTemplates{
		Active:   fmt.Sprintf("%v {{ .String | cyan }}", promptui.IconSelect),
		Inactive: "{{ .String }}",
		Selected: "{{ .String }}",
	}
	sigAlg := promptui.Select{
		Label:     "Select Signature Algorithm",
		Items:     sigAlgs,
		Templates: template,
	}
	i, _, err := sigAlg.Run()
	if err != nil {
		return caConfiguration, err
	}
	//var signatureAlgorithmChoice int
	err = caConfiguration.SetSignatureAlgorithm(i)
	if err != nil {
		return caConfiguration, err
	}

	pubAlgs := caConfiguration.GetPublicKeyAlgorithms()
	template = &promptui.SelectTemplates{
		Active:   fmt.Sprintf("%v {{ .String | cyan }}", promptui.IconSelect),
		Inactive: "{{ .String }}",
		Selected: "{{ .String }}",
	}
	pubAlg := promptui.Select{
		Label:     "Select Public Key Algorithm",
		Items:     pubAlgs,
		Templates: template,
	}
	i, _, err = pubAlg.Run()
	if err != nil {
		return caConfiguration, err
	}
	err = caConfiguration.SetPublicKeyAlgorithm(i)
	if err != nil {
		return caConfiguration, err
	}

	commonNamePrompt := promptui.Prompt{
		Label: "Common Name",
	}
	commonName, err := commonNamePrompt.Run()
	if err != nil {
		fmt.Printf("Prompt failed %v\n", err)
		return caConfiguration, err
	}
	err = caConfiguration.SetSubjectCommonName(commonName)
	if err != nil {
		return caConfiguration, err
	}

	countryPrompt := promptui.Prompt{
		Label: "Enter Countries (Separated by commas)",
	}
	countryCS, err := countryPrompt.Run()
	if err != nil {
		fmt.Printf("Prompt failed %v\n", err)
		return caConfiguration, err
	}
	caConfiguration.SetSubjectCountries(countryCS)

	organizationPrompt := promptui.Prompt{
		Label: "Enter Organizations (Separated by commas)",
	}
	organizationCS, err := organizationPrompt.Run()
	if err != nil {
		fmt.Printf("Prompt failed %v\n", err)
		return caConfiguration, err
	}
	caConfiguration.SetSubjectOrganizations(organizationCS)

	organizationalUnitPrompt := promptui.Prompt{
		Label: "Enter Organizational Units (Separated by commas)",
	}
	organizationalUnitCS, err := organizationalUnitPrompt.Run()
	if err != nil {
		fmt.Printf("Prompt failed %v\n", err)
		return caConfiguration, err
	}
	caConfiguration.SetSubjectOrganizationalUnits(organizationalUnitCS)

	localityPrompt := promptui.Prompt{
		Label: "Enter Locality (Separated by commas)",
	}
	localityCS, err := localityPrompt.Run()
	if err != nil {
		fmt.Printf("Prompt failed %v\n", err)
		return caConfiguration, err
	}
	caConfiguration.SetSubjectLocalities(localityCS)

	provincePrompt := promptui.Prompt{
		Label: "Enter Province (Separated by commas)",
	}
	provinceCS, err := provincePrompt.Run()
	if err != nil {
		fmt.Printf("Prompt failed %v\n", err)
		return caConfiguration, err
	}
	caConfiguration.SetSubjectProvinces(provinceCS)

	streetAddressPrompt := promptui.Prompt{
		Label: "Enter Street Address (Separated by commas)",
	}
	streetAddressCS, err := streetAddressPrompt.Run()
	if err != nil {
		fmt.Printf("Prompt failed %v\n", err)
		return caConfiguration, err
	}
	caConfiguration.SetSubjectStreetAddresses(streetAddressCS)

	postalCodePrompt := promptui.Prompt{
		Label: "Enter Postal Codes (Separated by commas)",
	}
	postalCodeCS, err := postalCodePrompt.Run()
	if err != nil {
		fmt.Printf("Prompt failed %v\n", err)
		return caConfiguration, err
	}
	caConfiguration.SetSubjectPostalCodes(postalCodeCS)

	caConfiguration.SetNotBefore()

	yearsPrompt := promptui.Prompt{
		Label: "Enter Years",
	}
	years, err := yearsPrompt.Run()
	if err != nil {
		fmt.Printf("Prompt failed %v\n", err)
		return caConfiguration, err
	}

	monthsPrompt := promptui.Prompt{
		Label: "Enter Months",
	}
	months, err := monthsPrompt.Run()
	if err != nil {
		fmt.Printf("Prompt failed %v\n", err)
		return caConfiguration, err
	}

	daysPrompt := promptui.Prompt{
		Label: "Enter Days (Separated by commas)",
	}
	days, err := daysPrompt.Run()
	if err != nil {
		fmt.Printf("Prompt failed %v\n", err)
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

	caConfiguration.SetDefaultCAKeyUsages()
	caConfiguration.SetCA()
	caConfiguration.SetBasicConstraintsValid()

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

	return caConfiguration, nil
}

// CreateRootCACertificate this creates a root CA certificate and return the public and private key
func CreateRootCACertificate(rootConfig caconfiguration.Init) ([]byte, []byte, error) {
	newCertBytes, privateKey, err := CreateSignedCertificate(rootConfig, rootConfig.Certificate, nil)
	if err != nil {
		return nil, nil, err
	}
	return newCertBytes, privateKey, nil
}

// CreateSubCACertificate this creates a CA certificate and return the public and private key
func CreateSubCACertificate(subCAConfig caconfiguration.Init, parentCert x509.Certificate, parentKey interface{}) ([]byte, []byte, error) {
	newCertBytes, privateKey, err := CreateSignedCertificate(subCAConfig, parentCert, parentKey)
	if err != nil {
		return nil, nil, err
	}
	return newCertBytes, privateKey, nil
}

func main() {
	// Create 	- Create a CA
	//				- Root
	//				- SubCA
	// List 	- List CAs
	// Sign 	- Sign a certificate
	// rootConfig, err := Configuration()
	// if err != nil {
	// 	log.Fatal(err)
	// }
	// rootPubKey, rootPrivKey, err := CreateRootCACertificate(rootConfig)
	// if err != nil {
	// 	log.Fatal(err)
	// }

	// subCAConfig, err := Configuration()
	// if err != nil {
	// 	log.Fatal(err)
	// }

	// parentPriv, err := x509.ParsePKCS8PrivateKey(rootPrivKey)
	// if err != nil {
	// 	log.Fatal(err)
	// }
	// subCAPubKey, subCAPrivKey, err := CreateSubCACertificate(subCAConfig, rootConfig.Certificate, parentPriv)
	// if err != nil {
	// 	log.Fatal(err)
	// }

	// subCAPubPem := pem.Block{Type: "CERTIFICATE", Bytes: subCAPubKey}
	// subCAPubBytes := pem.EncodeToMemory(&subCAPubPem)
	// subCAPrivPem := pem.Block{Type: "PRIVATE KEY", Bytes: subCAPrivKey}
	// subCAPrivBytes := pem.EncodeToMemory(&subCAPrivPem)
	// ioutil.WriteFile("/mnt/c/temp/subca/subca.crt", subCAPubBytes, os.ModePerm)
	// ioutil.WriteFile("/mnt/c/temp/subca/subca.key", subCAPrivBytes, os.ModePerm)
}
