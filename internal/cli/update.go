package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/Darren-Certlocker/trust-cli/internal/output"
	"github.com/spf13/cobra"
)

// Edge modification uses POST /resource/modify. Require an explicit full form;
// never silently replace an asset by revoking and recreating it.
func updateCommand(path string) *cobra.Command {
	cmd := &cobra.Command{
		Use: "update ID", Aliases: []string{"modify", "put"},
		Short: "Update an asset using a full JSON form (--body file, or - for stdin)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			file, _ := cmd.Flags().GetString("body")
			if file == "" {
				return fmt.Errorf("--body is required (file or - for stdin)")
			}
			var raw []byte
			var err error
			if file == "-" {
				raw, err = io.ReadAll(cmd.InOrStdin())
			} else {
				raw, err = os.ReadFile(file)
			}
			if err != nil {
				return err
			}
			var body map[string]any
			if err = json.Unmarshal(raw, &body); err != nil || body == nil {
				return fmt.Errorf("--body must contain a JSON object")
			}
			if supplied, ok := body["id"]; ok && supplied != args[0] {
				return fmt.Errorf("body id must match the command id")
			}
			body["id"] = args[0]
			result, err := post(cmd, path+"/modify", body)
			if err != nil {
				return err
			}
			if err = errorMessage(result); err != nil {
				return err
			}
			return output.Write(redact(result, "secret", "private_key", "privateKey", "certificate_properties", "certificateProperties"))
		},
	}
	cmd.Flags().String("body", "", "Full update form as JSON, or - for stdin")
	return cmd
}
