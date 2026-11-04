package cli

import (
	"net/url"
	"strings"

	"github.com/spf13/cobra"

	"github.com/certlocker-io/trust-cli/internal/edge"
)

func newAudit() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "audit",
		Short: "Read Edge audit events",
	}
	list := &cobra.Command{
		Use:   "list",
		Short: "List audit events",
		RunE: func(cmd *cobra.Command, args []string) error {
			filter, err := auditFilter(cmd)
			if err != nil {
				return err
			}
			return postPrint(cmd, "audit/paged", edge.AuditQuery(filter))
		},
	}
	list.Flags().Int("limit", 50, "Page size. -1 asks Edge for as many rows as the store allows")
	list.Flags().Int("skip", 0, "Rows to skip")
	list.Flags().String("action", "", "Audit action name, for example HOST_ADD")
	list.Flags().String("outcome", "", "SUCCESS, FAILURE, or DENIED")
	list.Flags().String("severity", "", "INFO, WARN, or HIGH")
	list.Flags().String("category", "", "AUTH, ACCESS, CRUD, POLICY, SYSTEM, or SECURITY")
	list.Flags().String("actor", "", "USER, SERVICE, SYSTEM, API, AI_AGENT, or OIDC")
	list.Flags().String("email", "", "Actor email")
	list.Flags().String("from", "", "Occurred at, inclusive, RFC3339 or 2006-01-02T15:04:05")
	list.Flags().String("to", "", "Occurred at, inclusive")
	list.Flags().String("asset-id", "", "Asset id")
	list.Flags().String("asset-type", "", "Asset type, for example HOST, SECRET, TOKEN, PROBE, AGENT, ACME_AUTOMATION")
	list.Flags().String("group", "", "Group the caller can see")
	cmd.AddCommand(list)
	cmd.AddCommand(&cobra.Command{
		Use:   "get ID",
		Short: "Show one audit event",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return postPrint(cmd, "audit/detail/"+url.PathEscape(args[0]), map[string]any{})
		},
	})
	cmd.AddCommand(&cobra.Command{
		Use:   "actions",
		Short: "List audit action names",
		RunE: func(cmd *cobra.Command, args []string) error {
			return postPrint(cmd, "audit/actions", map[string]any{})
		},
	})
	return cmd
}

func auditFilter(cmd *cobra.Command) (edge.AuditFilter, error) {
	limit, _ := cmd.Flags().GetInt("limit")
	skip, _ := cmd.Flags().GetInt("skip")
	action, _ := cmd.Flags().GetString("action")
	outcome, _ := cmd.Flags().GetString("outcome")
	severity, _ := cmd.Flags().GetString("severity")
	category, _ := cmd.Flags().GetString("category")
	actor, _ := cmd.Flags().GetString("actor")
	email, _ := cmd.Flags().GetString("email")
	from, _ := cmd.Flags().GetString("from")
	to, _ := cmd.Flags().GetString("to")
	assetID, _ := cmd.Flags().GetString("asset-id")
	assetType, _ := cmd.Flags().GetString("asset-type")
	group, _ := cmd.Flags().GetString("group")
	return edge.AuditFilter{
		Limit:     limit,
		Skip:      skip,
		Action:    strings.ToUpper(strings.TrimSpace(action)),
		Outcome:   strings.ToUpper(strings.TrimSpace(outcome)),
		Severity:  strings.ToUpper(strings.TrimSpace(severity)),
		Category:  strings.ToUpper(strings.TrimSpace(category)),
		Actor:     strings.ToUpper(strings.TrimSpace(actor)),
		Email:     strings.ToLower(strings.TrimSpace(email)),
		From:      strings.TrimSpace(from),
		To:        strings.TrimSpace(to),
		AssetID:   strings.TrimSpace(assetID),
		AssetType: strings.ToUpper(strings.TrimSpace(assetType)),
		Group:     strings.TrimSpace(group),
	}, nil
}
