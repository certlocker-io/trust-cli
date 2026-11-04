package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/certlocker-io/trust-cli/internal/output"
)

func addProbeRun(parent *cobra.Command) {
	cmd := &cobra.Command{
		Use:   "run ID",
		Short: "Execute a probe",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runProbe(cmd, args[0])
		},
	}
	cmd.Flags().Bool("wait", false, "Poll until Edge records a new probe result")
	cmd.Flags().Duration("timeout", 2*time.Minute, "How long to wait for a result")
	parent.AddCommand(cmd)
}

func newAutomations() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "automations",
		Short: "List and run ACME automations",
	}
	list := &cobra.Command{
		Use:   "list",
		Short: "List automations",
		RunE: func(cmd *cobra.Command, args []string) error {
			limit, _ := cmd.Flags().GetInt("limit")
			skip, _ := cmd.Flags().GetInt("skip")
			name, _ := cmd.Flags().GetString("name")
			status, _ := cmd.Flags().GetString("status")
			group, _ := cmd.Flags().GetString("group")
			if status != "" {
				status = strings.ToUpper(status)
			}
			return postPrint(cmd, "acme/automations", listQuery(limit, skip, name, status, group))
		},
	}
	addListFlags(list)
	cmd.AddCommand(list)
	cmd.AddCommand(&cobra.Command{
		Use:   "get ID",
		Short: "Show one automation, including the last console output",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return postPrint(cmd, "acme/automation-detail/"+url.PathEscape(args[0]), map[string]any{})
		},
	})
	run := &cobra.Command{
		Use:   "run ID",
		Short: "Enqueue an automation run",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runAutomation(cmd, args[0])
		},
	}
	run.Flags().String("type", "", "certificate or challenge")
	run.Flags().String("certificate", "", "Certificate id for a certificate run")
	run.Flags().String("token", "", "Optional certificate token id for token.* script substitution")
	run.Flags().String("challenge-content", "", "HTTP-01 challenge content")
	run.Flags().String("challenge-uri", "", "HTTP-01 challenge URI")
	run.Flags().Bool("wait", false, "Poll until last_run_at changes, then print the console")
	run.Flags().Duration("timeout", 2*time.Minute, "How long to wait for the run to finish")
	cmd.AddCommand(run)
	return cmd
}

func listQuery(limit, skip int, name, status, group string) any {
	return mapFromList(limit, skip, name, status, group)
}

func mapFromList(limit, skip int, name, status, group string) map[string]any {
	query := map[string]any{"limit": limit}
	if skip != 0 {
		query["skip"] = skip
	}
	var musts []map[string]string
	if name != "" {
		musts = append(musts, map[string]string{"field": "name", "value": name})
	}
	if status != "" {
		musts = append(musts, map[string]string{"field": "status", "value": status})
	}
	if len(musts) > 0 {
		query["musts"] = musts
	}
	if group != "" {
		query["ins"] = []map[string]any{{"field": "groups", "values": []string{group}}}
	}
	return query
}

func runProbe(cmd *cobra.Command, id string) error {
	wait, _ := cmd.Flags().GetBool("wait")
	timeout, _ := cmd.Flags().GetDuration("timeout")
	var before string
	if wait {
		detail, err := post(cmd, "probe/detail/"+url.PathEscape(id), map[string]any{})
		if err == nil {
			before = nestedString(detail, "result", "at")
		}
	}
	ack, err := post(cmd, "probe/probe", map[string]any{"id": id})
	if err != nil {
		return err
	}
	if !wait {
		return output.Write(ack)
	}
	raw, err := poll(cmd, timeout, "probe/detail/"+url.PathEscape(id), func(detail map[string]any) bool {
		at := nestedString(mustJSON(detail), "result", "at")
		return at != "" && at != before
	})
	if err != nil {
		return err
	}
	result := nestedRaw(raw, "result")
	if len(result) == 0 {
		result = raw
	}
	if err := output.Write(result); err != nil {
		return err
	}
	if success, ok := jsonBool(result, "success"); ok && !success {
		return fmt.Errorf("probe failed")
	}
	return nil
}

func runAutomation(cmd *cobra.Command, id string) error {
	kind, _ := cmd.Flags().GetString("type")
	kind = strings.ToUpper(strings.TrimSpace(kind))
	switch kind {
	case "CERTIFICATE", "CHALLENGE":
	default:
		return fmt.Errorf("--type must be certificate or challenge")
	}
	body := map[string]any{"type": kind}
	if kind == "CERTIFICATE" {
		certificate, _ := cmd.Flags().GetString("certificate")
		if certificate == "" {
			return fmt.Errorf("--certificate is required for a certificate run")
		}
		body["certificate_id"] = certificate
		token, _ := cmd.Flags().GetString("token")
		if token != "" {
			body["cert_token_id"] = token
		}
	} else {
		content, _ := cmd.Flags().GetString("challenge-content")
		uri, _ := cmd.Flags().GetString("challenge-uri")
		if content == "" || uri == "" {
			return fmt.Errorf("--challenge-content and --challenge-uri are required for a challenge run")
		}
		body["challenge_content"] = content
		body["challenge_uri"] = uri
	}
	wait, _ := cmd.Flags().GetBool("wait")
	timeout, _ := cmd.Flags().GetDuration("timeout")
	detailPath := "acme/automation-detail/" + url.PathEscape(id)
	var before string
	if wait {
		detail, err := post(cmd, detailPath, map[string]any{})
		if err == nil {
			before = jsonString(detail, "last_run_at")
		}
	}
	ack, err := post(cmd, "acme/automation-run/"+url.PathEscape(id), body)
	if err != nil {
		return err
	}
	if !wait {
		return output.Write(ack)
	}
	raw, err := poll(cmd, timeout, detailPath, func(detail map[string]any) bool {
		at := stringValue(detail["last_run_at"])
		return at != "" && at != before
	})
	if err != nil {
		return err
	}
	summary, err := json.Marshal(map[string]any{
		"last_run_success": jsonAny(raw, "last_run_success"),
		"last_run_at":      jsonAny(raw, "last_run_at"),
		"console":          jsonAny(raw, "console"),
	})
	if err != nil {
		return err
	}
	if err := output.Write(summary); err != nil {
		return err
	}
	if success, ok := jsonBool(raw, "last_run_success"); ok && !success {
		return fmt.Errorf("automation run failed")
	}
	return nil
}

func poll(cmd *cobra.Command, timeout time.Duration, path string, done func(map[string]any) bool) ([]byte, error) {
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}
	deadline := time.Now().Add(timeout)
	for {
		raw, err := post(cmd, path, map[string]any{})
		if err != nil {
			return nil, err
		}
		var detail map[string]any
		if json.Unmarshal(raw, &detail) == nil && done(detail) {
			return raw, nil
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("timed out waiting for %s", path)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
}

func nestedString(raw []byte, objectKey, field string) string {
	var body map[string]any
	if json.Unmarshal(raw, &body) != nil {
		return ""
	}
	child, _ := body[objectKey].(map[string]any)
	if child == nil {
		return ""
	}
	return stringValue(child[field])
}

func nestedRaw(raw []byte, key string) []byte {
	var body map[string]any
	if json.Unmarshal(raw, &body) != nil {
		return nil
	}
	value, ok := body[key]
	if !ok || value == nil {
		return nil
	}
	out, err := json.Marshal(value)
	if err != nil {
		return nil
	}
	return out
}

func jsonString(raw []byte, key string) string {
	return stringValue(jsonAny(raw, key))
}

func jsonAny(raw []byte, key string) any {
	var body map[string]any
	if json.Unmarshal(raw, &body) != nil {
		return nil
	}
	return body[key]
}

func jsonBool(raw []byte, key string) (bool, bool) {
	value := jsonAny(raw, key)
	typed, ok := value.(bool)
	return typed, ok
}

func stringValue(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case nil:
		return ""
	default:
		return fmt.Sprint(typed)
	}
}
