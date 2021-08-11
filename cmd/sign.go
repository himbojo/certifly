/*
Copyright © 2021 NAME HERE jordan.akroyd@gmail.com

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package cmd

import (
	"certifly/certificate/request"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/manifoldco/promptui"
	"github.com/spf13/cobra"
)

// signCmd represents the sign command
var signCmd = &cobra.Command{
	Use:   "sign",
	Short: "Sign a certificate",
	Long:  `This command will guide you through the process of signing a certificate request`,
	Run: func(cmd *cobra.Command, args []string) {
		signCertificate()
	},
}

func init() {
	rootCmd.AddCommand(signCmd)
}

func signCertificate() {
	csrLocationPrompt := promptui.Prompt{
		Label: "Enter CSR Path",
	}
	csrLocation, err := csrLocationPrompt.Run()
	if err != nil {
		log.Fatalf("Prompt failed %v", err)
	}
	// load in a CSR
	data, err := ioutil.ReadFile(csrLocation)
	if err != nil {
		log.Fatalf("Reading of file failed %v", err)
	}
	b, _ := pem.Decode(data)
	var csr *x509.CertificateRequest
	if b == nil {
		csr, err = x509.ParseCertificateRequest(data)
	} else {
		csr, err = x509.ParseCertificateRequest(b.Bytes)
	}
	if err != nil {
		log.Fatalf("Parsing CSR failed %v", err)
	}

	caPubPathPrompt := promptui.Prompt{
		Label: "Enter Certificate Authority Public Key Path",
	}
	caPubPath, err := caPubPathPrompt.Run()
	if err != nil {
		log.Fatalf("Prompt failed %v", err)
	}
	// load in a public key
	data, err = ioutil.ReadFile(caPubPath)
	if err != nil {
		log.Fatalf("Reading of file failed %v", err)
	}
	b, _ = pem.Decode(data)
	var pub *x509.Certificate
	if b == nil {
		pub, err = x509.ParseCertificate(data)
	} else {
		pub, err = x509.ParseCertificate(b.Bytes)
	}
	if err != nil {
		log.Fatalf("Parsing Public Cert failed %v", err)
	}
	caPrivPathPrompt := promptui.Prompt{
		Label: "Enter Certificate Authority Private Key Path",
	}
	caPrivPath, err := caPrivPathPrompt.Run()
	if err != nil {
		log.Fatalf("Prompt failed %v", err)
	}
	// load in a private key
	data, err = ioutil.ReadFile(caPrivPath)
	if err != nil {
		log.Fatalf("Reading of file failed %v", err)
	}
	b, _ = pem.Decode(data)

	var priv interface{}
	if b == nil {
		priv, err = x509.ParsePKCS8PrivateKey(data)
	} else {
		priv, err = x509.ParsePKCS8PrivateKey(b.Bytes)
	}
	if err != nil {
		log.Fatalf("Parsing Private Key failed %v", err)
	}
	switch priv := priv.(type) {
	case *rsa.PrivateKey:
		fmt.Println("test", priv)
	case *dsa.PrivateKey:
		fmt.Println("test", priv)
	case *ecdsa.PrivateKey:
		fmt.Println("test", priv)
	case ed25519.PrivateKey:
		fmt.Println("test", priv)
	default:
		panic("unknown type of key")
	}
	template := request.Init{}
	template.SetSerialNumber()
	template.Certificate.Version = csr.Version
	template.Certificate.Signature = csr.Signature
	template.Certificate.SignatureAlgorithm = csr.SignatureAlgorithm
	template.Certificate.PublicKeyAlgorithm = csr.PublicKeyAlgorithm
	template.Certificate.PublicKey = csr.PublicKey
	template.Certificate.Subject = csr.Subject
	template.Certificate.Extensions = csr.Extensions
	template.Certificate.ExtraExtensions = csr.ExtraExtensions
	template.Certificate.DNSNames = csr.DNSNames
	template.Certificate.EmailAddresses = csr.EmailAddresses
	template.Certificate.IPAddresses = csr.IPAddresses
	template.Certificate.URIs = csr.URIs
	template.Certificate.BasicConstraintsValid = false
	fmt.Println("hello")
	certBytes, err := x509.CreateCertificate(rand.Reader, &template.Certificate, pub, template.Certificate.PublicKey, priv)
	if err != nil {
		log.Fatalf("Parsing Private Key failed %v", err)
	}
	certPubPem := pem.Block{Type: "CERTIFICATE", Bytes: certBytes}
	certPubBytes := pem.EncodeToMemory(&certPubPem)
	filename := template.GetCertificateRequest().Subject.CommonName
	filelocation := fmt.Sprintf("/mnt/c/temp/entity/%v", filename)
	publicKeyExtension := fmt.Sprintf("%v.crt", filelocation)
	ioutil.WriteFile(publicKeyExtension, certPubBytes, os.ModePerm)

}
