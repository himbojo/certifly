/*
Copyright © 2021 NAME HERE <EMAIL ADDRESS>

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
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	createca "go-ca/creation"

	"github.com/manifoldco/promptui"
	"github.com/spf13/cobra"
)

// createCmd represents the create command
var createCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a Root or Subordinate CA",
	Long: `This command will guide you through the process of creating
	a certificate authority, you can either create a brand new Root CA
	or a Subordinate CA issued by a certificate authority with a path
	length contraint of 1 or more.`,
	Run: func(cmd *cobra.Command, args []string) {
		createCertificateAuthority()
	},
}

func init() {
	rootCmd.AddCommand(createCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// createCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// createCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")

}

func createCertificateAuthority() {
	template := &promptui.SelectTemplates{
		Active:   fmt.Sprintf("%v {{ . | cyan }}", promptui.IconSelect),
		Inactive: "{{ . }}",
		Selected: "{{ . }}",
	}
	prompt := promptui.Select{
		Label:     "Select Certificate Authority Type",
		Items:     []string{"Root", "Subordinate"},
		Templates: template,
	}

	_, result, err := prompt.Run()
	if err != nil {
		log.Fatalf("Prompt failed %v\n", err)
	}

	if result == "Root" {
		rootConfig, err := createca.Configuration()
		if err != nil {
			log.Fatal(err)
		}
		rootPubKey, rootPrivKey, err := createca.CreateRootCACertificate(rootConfig)
		if err != nil {
			log.Fatal(err)
		}

		rootPubPem := pem.Block{Type: "CERTIFICATE", Bytes: rootPubKey}
		rootPubBytes := pem.EncodeToMemory(&rootPubPem)
		rootPrivPem := pem.Block{Type: "PRIVATE KEY", Bytes: rootPrivKey}
		rootPrivBytes := pem.EncodeToMemory(&rootPrivPem)

		filename := rootConfig.Certificate.Subject.CommonName
		filelocation := fmt.Sprintf("/mnt/c/temp/root/%v", filename)
		publicKeyExtension := fmt.Sprintf("%v.crt", filelocation)
		privateKeyExtension := fmt.Sprintf("%v.key", filelocation)
		ioutil.WriteFile(publicKeyExtension, rootPubBytes, os.ModePerm)
		ioutil.WriteFile(privateKeyExtension, rootPrivBytes, os.ModePerm)

	} else if result == "Subordinate" {
		subCAConfig, err := createca.Configuration()
		if err != nil {
			log.Fatal(err)
		}
		_ = subCAConfig
		//parentPriv, err := x509.ParsePKCS8PrivateKey(rootPrivKey)
		//if err != nil {
		//	log.Fatal(err)
		//}
		//subCAPubKey, subCAPrivKey, err := createca.CreateSubCACertificate(subCAConfig, rootConfig.Certificate, parentPriv)
		//if err != nil {
		//	log.Fatal(err)
		//}
	}
}
