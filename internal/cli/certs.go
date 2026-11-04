package cli

import (
	"bytes"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/Darren-Certlocker/trust-cli/internal/output"
)

func newCertificates() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "certificates",
		Aliases: []string{"certs"},
		Short:   "Manage certificates",
	}
	cmd.AddCommand(updateCommand("cert"))
	cmd.AddCommand(listCommand("cert", "List certificates"))
	cmd.AddCommand(&cobra.Command{
		Use:   "get ID",
		Short: "Show one certificate",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			raw, err := post(cmd, "cert/detail/"+url.PathEscape(args[0]), map[string]any{})
			if err != nil {
				return err
			}
			return output.Write(redact(raw, "private_key"))
		},
	})
	cmd.AddCommand(certificateCreate())
	cmd.AddCommand(certificateGenerate())
	cmd.AddCommand(&cobra.Command{
		Use:   "download ID",
		Short: "Download the public certificate PEM",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return postPrint(cmd, "cert/download", map[string]any{"id": args[0]})
		},
	})
	cmd.AddCommand(&cobra.Command{
		Use:   "delete ID",
		Short: "Delete a certificate",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return postPrint(cmd, "cert/delete", map[string]any{"id": args[0]})
		},
	})
	cmd.AddCommand(&cobra.Command{
		Use:   "delete-expired",
		Short: "Delete expired certificates in the account",
		RunE: func(cmd *cobra.Command, args []string) error {
			return postPrint(cmd, "cert/delete-expired", map[string]any{})
		},
	})
	return cmd
}

func certificateCreate() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Import a certificate",
		RunE: func(cmd *cobra.Command, args []string) error {
			body, err := objectFromFlags(cmd, func(cmd *cobra.Command, body map[string]any) error {
				putString(cmd, body, "name", "name")
				putString(cmd, body, "description", "description")
				putGroups(cmd, body)
				putString(cmd, body, "domain", "primary_domain")
				if cmd.Flags().Changed("san") {
					sans, _ := cmd.Flags().GetStringArray("san")
					body["san_domains"] = sans
				}
				publicCert, ok, err := readTextFlag(cmd, "public-cert", "public-cert-file")
				if err != nil {
					return err
				}
				if ok {
					body["public_cert"] = publicCert
				}
				privateKey, ok, err := readTextFlag(cmd, "private-key", "private-key-file")
				if err != nil {
					return err
				}
				if ok {
					body["private_key"] = privateKey
				}
				if err := require(body, "name"); err != nil {
					return err
				}
				return require(body, "public_cert")
			})
			if err != nil {
				return err
			}
			raw, err := post(cmd, "cert/create", body)
			if err != nil {
				return err
			}
			fmt.Fprintln(os.Stderr, "Private key is not printed.")
			return output.Write(redact(raw, "private_key"))
		},
	}
	cmd.Flags().String("body", "", "JSON file merged under the flags")
	cmd.Flags().String("name", "", "Name")
	cmd.Flags().String("description", "", "Description")
	cmd.Flags().StringArray("group", nil, "Group. Repeat for more than one")
	cmd.Flags().String("domain", "", "Primary domain")
	cmd.Flags().StringArray("san", nil, "Subject alternative name. Repeat for more than one")
	cmd.Flags().String("public-cert", "", "Public certificate PEM")
	cmd.Flags().String("public-cert-file", "", "File containing the public certificate PEM, or - for stdin")
	cmd.Flags().String("private-key", "", "Private key PEM")
	cmd.Flags().String("private-key-file", "", "File containing the private key PEM")
	return cmd
}

func certificateGenerate() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "generate",
		Short: "Generate a self-signed certificate",
		RunE: func(cmd *cobra.Command, args []string) error {
			body, err := objectFromFlags(cmd, applyCertGenerate)
			if err != nil {
				return err
			}
			raw, err := post(cmd, "cert/generate", body)
			if err != nil {
				return err
			}
			fmt.Fprintln(os.Stderr, "Private key is not printed. It is stored with the certificate.")
			return output.Write(redact(raw, "private_key"))
		},
	}
	cmd.Flags().String("body", "", "JSON file merged under the flags")
	cmd.Flags().String("name", "", "Name")
	cmd.Flags().String("description", "", "Description")
	cmd.Flags().StringArray("group", nil, "Group. Repeat for more than one")
	cmd.Flags().String("cn", "", "Subject common name")
	cmd.Flags().String("key-algorithm", "ECDSA", "RSA, ECDSA, or ML_DSA")
	cmd.Flags().Int("rsa-key-size", 2048, "RSA modulus size: 2048, 3072, or 4096")
	cmd.Flags().String("curve", "P-256", "ECDSA curve: P-256 or P-384")
	cmd.Flags().String("ml-dsa", "ML_DSA_65", "ML-DSA parameter set: ML_DSA_44, ML_DSA_65, or ML_DSA_87")
	cmd.Flags().String("hash", "SHA256", "SHA256, SHA384, or SHA512. Unused for ML_DSA")
	cmd.Flags().Int("days", 365, "Validity in days, from 1 to 8250")
	cmd.Flags().String("org", "", "Subject organisation")
	cmd.Flags().String("ou", "", "Subject organisational unit")
	cmd.Flags().String("locality", "", "Subject locality")
	cmd.Flags().String("state", "", "Subject state or province")
	cmd.Flags().String("country", "", "Subject country")
	cmd.Flags().String("email", "", "Subject email")
	return cmd
}

func applyCertGenerate(cmd *cobra.Command, body map[string]any) error {
	putString(cmd, body, "name", "name")
	putString(cmd, body, "description", "description")
	putGroups(cmd, body)
	putString(cmd, body, "cn", "subject_cn")
	putString(cmd, body, "org", "subject_o")
	putString(cmd, body, "ou", "subject_ou")
	putString(cmd, body, "locality", "subject_l")
	putString(cmd, body, "state", "subject_st")
	putString(cmd, body, "country", "subject_c")
	putString(cmd, body, "email", "subject_email")
	if cmd.Flags().Changed("key-algorithm") {
		value, _ := cmd.Flags().GetString("key-algorithm")
		body["key_algorithm"] = strings.ToUpper(strings.TrimSpace(value))
	}
	putInt(cmd, body, "days", "validity_days")
	putInt(cmd, body, "rsa-key-size", "rsa_key_size")
	if cmd.Flags().Changed("curve") {
		value, _ := cmd.Flags().GetString("curve")
		body["ec_curve"] = strings.ToUpper(strings.TrimSpace(value))
	}
	if cmd.Flags().Changed("ml-dsa") {
		value, _ := cmd.Flags().GetString("ml-dsa")
		body["ml_dsa_parameter_set"] = strings.ToUpper(strings.TrimSpace(value))
	}
	if cmd.Flags().Changed("hash") {
		value, _ := cmd.Flags().GetString("hash")
		hash, err := hashAlgorithm(value)
		if err != nil {
			return err
		}
		body["hash_algorithm"] = hash
	}
	return normalizeCertGenerate(body)
}

func normalizeCertGenerate(body map[string]any) error {
	name, ok := trimmedString(body["name"])
	if !ok || name == "" {
		return fmt.Errorf("name is required")
	}
	cn, ok := trimmedString(body["subject_cn"])
	if !ok || cn == "" {
		return fmt.Errorf("cn is required")
	}
	body["name"] = name
	body["subject_cn"] = cn
	if _, exists := body["key_algorithm"]; !exists {
		body["key_algorithm"] = "ECDSA"
	}
	algorithm, ok := trimmedString(body["key_algorithm"])
	if !ok || algorithm == "" {
		return fmt.Errorf("key-algorithm must be RSA, ECDSA, or ML_DSA")
	}
	algorithm = strings.ToUpper(algorithm)
	body["key_algorithm"] = algorithm
	if _, exists := body["validity_days"]; !exists {
		body["validity_days"] = 365
	}
	days, ok := asInt(body["validity_days"])
	if !ok || days < 1 || days > 8250 {
		return fmt.Errorf("days must be from 1 to 8250")
	}
	body["validity_days"] = days
	switch algorithm {
	case "RSA":
		if _, exists := body["rsa_key_size"]; !exists {
			body["rsa_key_size"] = 2048
		}
		size, ok := asInt(body["rsa_key_size"])
		if !ok {
			return fmt.Errorf("rsa-key-size must be 2048, 3072, or 4096")
		}
		switch size {
		case 2048, 3072, 4096:
		default:
			return fmt.Errorf("rsa-key-size must be 2048, 3072, or 4096")
		}
		body["rsa_key_size"] = size
		if err := setHash(body); err != nil {
			return err
		}
		delete(body, "ec_curve")
		delete(body, "ml_dsa_parameter_set")
	case "ECDSA":
		if _, exists := body["ec_curve"]; !exists {
			body["ec_curve"] = "P-256"
		}
		curve, ok := trimmedString(body["ec_curve"])
		if !ok {
			return fmt.Errorf("curve must be P-256 or P-384")
		}
		curve = strings.ToUpper(curve)
		if curve != "P-256" && curve != "P-384" {
			return fmt.Errorf("curve must be P-256 or P-384")
		}
		body["ec_curve"] = curve
		if err := setHash(body); err != nil {
			return err
		}
		delete(body, "rsa_key_size")
		delete(body, "ml_dsa_parameter_set")
	case "ML_DSA":
		if _, exists := body["ml_dsa_parameter_set"]; !exists {
			body["ml_dsa_parameter_set"] = "ML_DSA_65"
		}
		parameter, ok := trimmedString(body["ml_dsa_parameter_set"])
		if !ok {
			return fmt.Errorf("ml-dsa must be ML_DSA_44, ML_DSA_65, or ML_DSA_87")
		}
		parameter = strings.ToUpper(parameter)
		switch parameter {
		case "ML_DSA_44", "ML_DSA_65", "ML_DSA_87":
		default:
			return fmt.Errorf("ml-dsa must be ML_DSA_44, ML_DSA_65, or ML_DSA_87")
		}
		body["ml_dsa_parameter_set"] = parameter
		delete(body, "hash_algorithm")
		delete(body, "rsa_key_size")
		delete(body, "ec_curve")
	default:
		return fmt.Errorf("key-algorithm must be RSA, ECDSA, or ML_DSA")
	}
	return nil
}

func setHash(body map[string]any) error {
	if _, exists := body["hash_algorithm"]; !exists {
		body["hash_algorithm"] = "SHA256"
		return nil
	}
	value, ok := trimmedString(body["hash_algorithm"])
	if !ok {
		return fmt.Errorf("hash must be SHA256, SHA384, or SHA512")
	}
	hash, err := hashAlgorithm(value)
	if err != nil {
		return err
	}
	body["hash_algorithm"] = hash
	return nil
}

func hashAlgorithm(value string) (string, error) {
	switch strings.ToUpper(strings.TrimSpace(value)) {
	case "SHA256":
		return "SHA256", nil
	case "SHA384":
		return "SHA384", nil
	case "SHA512":
		return "SHA512", nil
	default:
		return "", fmt.Errorf("hash must be SHA256, SHA384, or SHA512")
	}
}

func trimmedString(value any) (string, bool) {
	text, ok := value.(string)
	if !ok {
		return "", false
	}
	return strings.TrimSpace(text), true
}

func asInt(value any) (int, bool) {
	switch typed := value.(type) {
	case int:
		return typed, true
	case int64:
		return int(typed), true
	case float64:
		if typed != float64(int(typed)) {
			return 0, false
		}
		return int(typed), true
	default:
		return 0, false
	}
}

func readTextFlag(cmd *cobra.Command, inline, file string) (string, bool, error) {
	if cmd.Flags().Changed(inline) && cmd.Flags().Changed(file) {
		return "", false, fmt.Errorf("use one of --%s or --%s", inline, file)
	}
	if cmd.Flags().Changed(inline) {
		value, _ := cmd.Flags().GetString(inline)
		return value, true, nil
	}
	if !cmd.Flags().Changed(file) {
		return "", false, nil
	}
	path, _ := cmd.Flags().GetString(file)
	var raw []byte
	var err error
	if path == "-" {
		raw, err = io.ReadAll(os.Stdin)
	} else {
		raw, err = os.ReadFile(path)
	}
	if err != nil {
		return "", false, err
	}
	raw = bytes.TrimSuffix(raw, []byte("\n"))
	raw = bytes.TrimSuffix(raw, []byte("\r"))
	return string(raw), true, nil
}
