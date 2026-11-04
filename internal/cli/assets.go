package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/Darren-Certlocker/trust-cli/internal/edge"
	"github.com/Darren-Certlocker/trust-cli/internal/output"
)

type assetSpec struct {
	Use    string
	Path   string
	Noun   string
	Create func(*cobra.Command)
	Extra  func(*cobra.Command)
}

func newAsset(spec assetSpec) *cobra.Command {
	plural := spec.Noun + "s"
	article := "a " + spec.Noun
	if spec.Use == "agents" {
		plural = "AI agents"
		article = "an AI agent"
	}
	cmd := &cobra.Command{
		Use:   spec.Use,
		Short: "Manage " + plural,
	}
	cmd.AddCommand(listCommand(spec.Path, "List "+plural))
	cmd.AddCommand(getCommand(spec.Path, "Show one "+spec.Noun))
	create := &cobra.Command{
		Use:   "create",
		Short: "Create " + article,
	}
	create.Flags().String("body", "", "JSON file merged under the flags")
	spec.Create(create)
	cmd.AddCommand(create)
	cmd.AddCommand(updateCommand(spec.Path))
	cmd.AddCommand(actionCommand("revoke ID", "Revoke "+article, spec.Path, "revoke"))
	cmd.AddCommand(actionCommand("suspend ID", "Suspend "+article, spec.Path, "suspend"))
	cmd.AddCommand(actionCommand("unsuspend ID", "Unsuspend "+article, spec.Path, "resume"))
	cmd.AddCommand(actionCommand("resume ID", "Resume "+article, spec.Path, "resume"))
	if spec.Extra != nil {
		spec.Extra(cmd)
	}
	return cmd
}

func listCommand(path, short string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: short,
		RunE: func(cmd *cobra.Command, args []string) error {
			limit, _ := cmd.Flags().GetInt("limit")
			skip, _ := cmd.Flags().GetInt("skip")
			name, _ := cmd.Flags().GetString("name")
			status, _ := cmd.Flags().GetString("status")
			group, _ := cmd.Flags().GetString("group")
			if status != "" {
				status = strings.ToUpper(status)
			}
			return postPrint(cmd, path+"/paged", edge.ListQuery(edge.ListFilter{
				Limit: limit, Skip: skip, Name: name, Status: status, Group: group,
			}))
		},
	}
	addListFlags(cmd)
	return cmd
}

func addListFlags(cmd *cobra.Command) {
	cmd.Flags().Int("limit", 50, "Page size. -1 asks Edge for as many rows as the store allows")
	cmd.Flags().Int("skip", 0, "Rows to skip")
	cmd.Flags().String("name", "", "Exact name match")
	cmd.Flags().String("status", "", "Status: ACTIVE, SUSPENDED, EXPIRED, or REVOKED")
	cmd.Flags().String("group", "", "Group the caller can see")
}

func getCommand(path, short string) *cobra.Command {
	return &cobra.Command{
		Use:   "get ID",
		Short: short,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return postPrint(cmd, path+"/detail/"+url.PathEscape(args[0]), map[string]any{})
		},
	}
}

func actionCommand(use, short, path, action string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   use,
		Short: short,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			body := map[string]any{"id": args[0]}
			if action == "revoke" {
				remove, _ := cmd.Flags().GetBool("remove-associated")
				if remove {
					body["remove_associated_items"] = true
				}
			}
			return postPrint(cmd, path+"/"+action, body)
		},
	}
	if action == "revoke" {
		cmd.Flags().Bool("remove-associated", false, "Also remove items associated with this asset")
	}
	return cmd
}

func addHostCreate(cmd *cobra.Command) {
	cmd.Flags().String("name", "", "Name")
	cmd.Flags().String("description", "", "Description")
	cmd.Flags().String("ip", "", "IP address or hostname")
	cmd.Flags().Int("port", 0, "Port")
	cmd.Flags().String("os", "", "Operating system")
	cmd.Flags().StringArray("group", nil, "Group. Repeat for more than one")
	cmd.Flags().String("secret", "", "Secret id used to connect")
	cmd.Flags().String("bastion", "", "Bastion id")
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		body, err := objectFromFlags(cmd, func(cmd *cobra.Command, body map[string]any) error {
			putString(cmd, body, "name", "name")
			putString(cmd, body, "description", "description")
			putString(cmd, body, "ip", "ip_address")
			putInt(cmd, body, "port", "port")
			putString(cmd, body, "os", "operating_system")
			putGroups(cmd, body)
			putString(cmd, body, "secret", "secret_id")
			putString(cmd, body, "bastion", "bastion_id")
			return require(body, "name")
		})
		if err != nil {
			return err
		}
		return postPrint(cmd, "host/create", body)
	}
}

func addSecretCreate(cmd *cobra.Command) {
	cmd.Flags().String("name", "", "Name")
	cmd.Flags().String("description", "", "Description")
	cmd.Flags().String("type", "", "Secret type: PRIVATE_KEY, PEM, PASSWORD, CREDENTIALS, or CONFIGURATION")
	cmd.Flags().StringArray("group", nil, "Group. Repeat for more than one")
	cmd.Flags().String("secret", "", "Secret value")
	cmd.Flags().String("secret-file", "", "File containing the secret value, or - for stdin")
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		body, err := objectFromFlags(cmd, func(cmd *cobra.Command, body map[string]any) error {
			putString(cmd, body, "name", "name")
			putString(cmd, body, "description", "description")
			putUpper(cmd, body, "type", "secret_type")
			putGroups(cmd, body)
			value, ok, err := readSecret(cmd)
			if err != nil {
				return err
			}
			if ok {
				body["secret"] = value
			}
			if err := require(body, "name"); err != nil {
				return err
			}
			if err := require(body, "secret_type"); err != nil {
				return err
			}
			return require(body, "secret")
		})
		if err != nil {
			return err
		}
		raw, err := post(cmd, "secret/create", body)
		if err != nil {
			return err
		}
		fmt.Fprintln(os.Stderr, "Secret value is not printed.")
		return output.Write(redact(raw, "secret"))
	}
}

func addProbeCreate(cmd *cobra.Command) {
	cmd.Flags().String("name", "", "Name")
	cmd.Flags().String("description", "", "Description")
	cmd.Flags().String("ip", "", "IP address or hostname")
	cmd.Flags().Int("port", 0, "Port")
	cmd.Flags().String("frequency", "", "HOURLY, DAILY, WEEKLY, or MONTHLY")
	cmd.Flags().StringArray("group", nil, "Group. Repeat for more than one")
	cmd.Flags().String("cert", "", "Certificate id")
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		body, err := objectFromFlags(cmd, func(cmd *cobra.Command, body map[string]any) error {
			putString(cmd, body, "name", "name")
			putString(cmd, body, "description", "description")
			putString(cmd, body, "ip", "ip_address")
			putInt(cmd, body, "port", "port")
			putUpper(cmd, body, "frequency", "frequency")
			putGroups(cmd, body)
			putString(cmd, body, "cert", "cert_id")
			return require(body, "name")
		})
		if err != nil {
			return err
		}
		return postPrint(cmd, "probe/create", body)
	}
}

func addTokenCreate(cmd *cobra.Command) {
	cmd.Flags().String("name", "", "Name")
	cmd.Flags().String("description", "", "Description")
	cmd.Flags().StringArray("group", nil, "Group. Repeat for more than one")
	cmd.Flags().Int("duration", 0, "Lifetime interval, used with --unit")
	cmd.Flags().String("unit", "DAYS", "MINUTES, HOURS, DAYS, WEEKS, MONTHS, or YEARS")
	cmd.Flags().String("type", "", "Token type: CERTIFICATE, HOST, BASTION, SECRET, ROOT, MCP, or WILDCARD")
	cmd.Flags().StringArray("protocol", nil, "Protocol: SSH, SFTP, HTTPS, ACME, MCP, RDP, or VNC")
	cmd.Flags().String("secret", "", "Secret id")
	cmd.Flags().StringArray("host", nil, "Host id. Repeat for more than one")
	cmd.Flags().String("bastion", "", "Bastion id")
	cmd.Flags().String("cert", "", "Certificate id")
	cmd.Flags().String("user", "", "User id")
	cmd.Flags().String("cidr", "", "CIDR restriction")
	cmd.Flags().Bool("single-use", false, "Token can be used once")
	cmd.Flags().Bool("auto-rotate", false, "Rotate the token automatically")
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		body, err := objectFromFlags(cmd, func(cmd *cobra.Command, body map[string]any) error {
			putString(cmd, body, "name", "name")
			putString(cmd, body, "description", "description")
			putGroups(cmd, body)
			if cmd.Flags().Changed("duration") || cmd.Flags().Changed("unit") {
				interval, _ := cmd.Flags().GetInt("duration")
				unit, _ := cmd.Flags().GetString("unit")
				body["duration"] = map[string]any{"interval": interval, "unit": strings.ToUpper(unit)}
			}
			putUpper(cmd, body, "type", "token_type")
			if cmd.Flags().Changed("protocol") {
				protocols, _ := cmd.Flags().GetStringArray("protocol")
				for i, protocol := range protocols {
					protocols[i] = strings.ToUpper(protocol)
				}
				body["protocols"] = protocols
			}
			putString(cmd, body, "secret", "secret_id")
			if cmd.Flags().Changed("host") {
				hosts, _ := cmd.Flags().GetStringArray("host")
				body["hosts"] = hosts
			}
			putString(cmd, body, "bastion", "bastion_id")
			putString(cmd, body, "cert", "cert_id")
			putString(cmd, body, "user", "user_id")
			putString(cmd, body, "cidr", "cidr")
			putBool(cmd, body, "single-use", "single_use")
			putBool(cmd, body, "auto-rotate", "auto_rotate")
			if err := require(body, "name"); err != nil {
				return err
			}
			return require(body, "token_type")
		})
		if err != nil {
			return err
		}
		raw, err := post(cmd, "token/create", body)
		if err != nil {
			return err
		}
		fmt.Fprintln(os.Stderr, "The token id is the credential. Store it now.")
		return output.Write(raw)
	}
}

func addAgentCreate(cmd *cobra.Command) {
	cmd.Flags().String("name", "", "Name")
	cmd.Flags().String("description", "", "Description")
	cmd.Flags().String("owner", "", "Owner user id")
	cmd.Flags().String("risk", "", "LOW, MEDIUM, or HIGH")
	cmd.Flags().StringArray("role", nil, "Role id. Repeat for more than one")
	cmd.Flags().StringArray("group", nil, "Group. Repeat for more than one")
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		body, err := objectFromFlags(cmd, func(cmd *cobra.Command, body map[string]any) error {
			putString(cmd, body, "name", "name")
			putString(cmd, body, "description", "description")
			putString(cmd, body, "owner", "owner_user_id")
			putUpper(cmd, body, "risk", "risk_level")
			if cmd.Flags().Changed("role") {
				roles, _ := cmd.Flags().GetStringArray("role")
				body["role_ids"] = roles
			}
			putGroups(cmd, body)
			if err := require(body, "name"); err != nil {
				return err
			}
			roles, _ := body["role_ids"].([]string)
			if len(roles) == 0 {
				if generic, ok := body["role_ids"].([]any); ok && len(generic) > 0 {
					return nil
				}
				return fmt.Errorf("role_ids is required")
			}
			return nil
		})
		if err != nil {
			return err
		}
		raw, err := post(cmd, "ai-agent/create", body)
		if err != nil {
			return err
		}
		if err := output.Write(raw); err != nil {
			return err
		}
		return errorMessage(raw)
	}
}

func objectFromFlags(cmd *cobra.Command, apply func(*cobra.Command, map[string]any) error) (map[string]any, error) {
	body := map[string]any{}
	path, _ := cmd.Flags().GetString("body")
	if path != "" {
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		if err := json.Unmarshal(raw, &body); err != nil {
			return nil, fmt.Errorf("--body: %w", err)
		}
	}
	if body == nil {
		return nil, fmt.Errorf("--body must contain a JSON object")
	}
	if err := apply(cmd, body); err != nil {
		return nil, err
	}
	return body, nil
}

func putString(cmd *cobra.Command, body map[string]any, flag, key string) {
	if !cmd.Flags().Changed(flag) {
		return
	}
	value, _ := cmd.Flags().GetString(flag)
	if value != "" {
		body[key] = value
	}
}

func putUpper(cmd *cobra.Command, body map[string]any, flag, key string) {
	if !cmd.Flags().Changed(flag) {
		return
	}
	value, _ := cmd.Flags().GetString(flag)
	if value != "" {
		body[key] = strings.ToUpper(value)
	}
}

func putInt(cmd *cobra.Command, body map[string]any, flag, key string) {
	if !cmd.Flags().Changed(flag) {
		return
	}
	value, _ := cmd.Flags().GetInt(flag)
	body[key] = value
}

func putBool(cmd *cobra.Command, body map[string]any, flag, key string) {
	if !cmd.Flags().Changed(flag) {
		return
	}
	value, _ := cmd.Flags().GetBool(flag)
	body[key] = value
}

func putGroups(cmd *cobra.Command, body map[string]any) {
	if !cmd.Flags().Changed("group") {
		return
	}
	groups, _ := cmd.Flags().GetStringArray("group")
	body["groups"] = groups
}

func require(body map[string]any, key string) error {
	value, ok := body[key]
	if !ok || value == nil || value == "" {
		return fmt.Errorf("%s is required", key)
	}
	return nil
}

func readSecret(cmd *cobra.Command) (string, bool, error) {
	if cmd.Flags().Changed("secret") && cmd.Flags().Changed("secret-file") {
		return "", false, fmt.Errorf("use one of --secret or --secret-file")
	}
	if cmd.Flags().Changed("secret") {
		value, _ := cmd.Flags().GetString("secret")
		return value, true, nil
	}
	if !cmd.Flags().Changed("secret-file") {
		return "", false, nil
	}
	path, _ := cmd.Flags().GetString("secret-file")
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

func redact(raw []byte, keys ...string) []byte {
	var body map[string]any
	if json.Unmarshal(raw, &body) != nil {
		return raw
	}
	changed := false
	for _, key := range keys {
		if _, ok := body[key]; ok {
			delete(body, key)
			changed = true
		}
	}
	if !changed {
		return raw
	}
	out, err := json.Marshal(body)
	if err != nil {
		return raw
	}
	return out
}

func errorMessage(raw []byte) error {
	var body map[string]any
	if json.Unmarshal(raw, &body) != nil {
		return nil
	}
	if message, ok := body["error_message"].(string); ok && strings.TrimSpace(message) != "" {
		return fmt.Errorf("%s", message)
	}
	return nil
}
