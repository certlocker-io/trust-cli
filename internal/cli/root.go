package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/certlocker-io/trust-cli/internal/output"
)

var (
	Version  = "dev"
	flagEdge string
	flagUI   string
)

func New() *cobra.Command {
	root := &cobra.Command{
		Use:          "trust",
		Short:        "Trust command line",
		SilenceUsage: true,
		Version:      Version,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			switch output.Format {
			case "table", "json":
				return nil
			default:
				return fmt.Errorf("--output must be table or json")
			}
		},
	}
	root.PersistentFlags().StringVar(&flagEdge, "edge", "", "Edge API base URL (env TRUST_EDGE_URL)")
	root.PersistentFlags().StringVar(&flagUI, "ui", "", "Edge UI base URL used by auth login (env TRUST_UI_URL)")
	root.PersistentFlags().StringVar(&output.Format, "output", "table", "Output format: table or json")
	root.AddCommand(
		newAuth(),
		newAsset(assetSpec{Use: "hosts", Path: "host", Noun: "host", Create: addHostCreate}),
		newCertificates(),
		newAsset(assetSpec{Use: "secrets", Path: "secret", Noun: "secret", Create: addSecretCreate}),
		newAsset(assetSpec{Use: "probes", Path: "probe", Noun: "probe", Create: addProbeCreate, Extra: addProbeRun}),
		newAsset(assetSpec{Use: "tokens", Path: "token", Noun: "token", Create: addTokenCreate}),
		newAsset(assetSpec{Use: "agents", Path: "ai-agent", Noun: "AI agent", Create: addAgentCreate}),
		newAudit(),
		newAutomations(),
		&cobra.Command{
			Use:   "version",
			Short: "Print the trust version",
			Run: func(cmd *cobra.Command, args []string) {
				fmt.Fprintln(os.Stdout, Version)
			},
		},
	)
	return root
}

func trimURL(value string) string {
	return strings.TrimRight(strings.TrimSpace(value), "/")
}
