# Safety Outputs Implementation Guide

> Comprehensive documentation of the safety outputs architecture in GitHub Agentic Workflows (gh-aw), intended as a reference for replicating similar patterns in other projects.

## Table of Contents

1. [Architectural Overview](#1-architectural-overview)
2. [Core Concept: Safe Outputs](#2-core-concept-safe-outputs)
3. [Type System & Schema Design](#3-type-system--schema-design)
4. [Configuration Extraction & Parsing](#4-configuration-extraction--parsing)
5. [Least-Privilege Permission Computation](#5-least-privilege-permission-computation)
6. [Tool Filtering & MCP Integration](#6-tool-filtering--mcp-integration)
7. [Validation Pipeline](#7-validation-pipeline)
8. [Handler Manager & Message Dispatch](#8-handler-manager--message-dispatch)
9. [Content Sanitization](#9-content-sanitization)
10. [Integrity & Secrecy (DIFC)](#10-integrity--secrecy-difc)
11. [Sandbox & Network Firewall](#11-sandbox--network-firewall)
12. [Template Injection Prevention](#12-template-injection-prevention)
13. [Markdown Security Scanner](#13-markdown-security-scanner)
14. [Expression Safety Allowlist](#14-expression-safety-allowlist)
15. [Dangerous Permissions Enforcement](#15-dangerous-permissions-enforcement)
16. [Strict Mode](#16-strict-mode)
17. [Threat Detection](#17-threat-detection)
18. [Supply Chain Security (Action Pinning)](#18-supply-chain-security-action-pinning)
19. [Audit & Compliance](#19-audit--compliance)
20. [Staged Mode (Dry-Run Previews)](#20-staged-mode-dry-run-previews)
21. [Guard Policies](#21-guard-policies)
22. [MCP Logs Guardrail](#22-mcp-logs-guardrail)
23. [Secret Leak Prevention](#23-secret-leak-prevention)

---

## 1. Architectural Overview

The gh-aw safety architecture follows a **defense-in-depth** strategy with multiple independent layers. The fundamental principle is:

> **The agent job is read-only. All writes go through safe-outputs, which uses a scoped GitHub App token.**

This creates a privilege-separated architecture where:

```
┌─────────────────────────────────────────────────────────┐
│                    Workflow Author                        │
│  (defines safe-outputs in YAML frontmatter)              │
└──────────────────────┬──────────────────────────────────┘
                       │ compiles to
                       ▼
┌─────────────────────────────────────────────────────────┐
│              Go Compiler (pkg/workflow/)                  │
│  ┌─────────────┐ ┌──────────────┐ ┌──────────────────┐  │
│  │ Config       │ │ Validation   │ │ Permission       │  │
│  │ Extraction   │ │ Pipeline     │ │ Computation      │  │
│  └─────────────┘ └──────────────┘ └──────────────────┘  │
│  ┌─────────────┐ ┌──────────────┐ ┌──────────────────┐  │
│  │ Tool         │ │ Sandbox/     │ │ Template         │  │
│  │ Filtering    │ │ Firewall     │ │ Injection Check  │  │
│  └─────────────┘ └──────────────┘ └──────────────────┘  │
└──────────────────────┬──────────────────────────────────┘
                       │ generates GitHub Actions YAML
                       ▼
┌─────────────────────────────────────────────────────────┐
│                  Runtime (GitHub Actions)                 │
│                                                          │
│  ┌──────────────────────┐   ┌────────────────────────┐  │
│  │  Agent Job (READ-ONLY)│   │  Safe Outputs Job      │  │
│  │  ┌────────────────┐  │   │  (SCOPED WRITE TOKEN)  │  │
│  │  │ AI Engine      │  │   │  ┌──────────────────┐  │  │
│  │  │ (sandboxed)    │  │   │  │ Handler Manager  │  │  │
│  │  └───────┬────────┘  │   │  │ ┌──────────────┐ │  │  │
│  │          │ JSONL      │   │  │ │ Validator    │ │  │  │
│  │          ▼            │   │  │ │ Sanitizer    │ │  │  │
│  │  ┌────────────────┐  │   │  │ │ Handlers     │ │  │  │
│  │  │ MCP Gateway    │──┼───┤  │ └──────────────┘ │  │  │
│  │  │ (guard policies│  │   │  └──────────────────┘  │  │
│  │  │  + DIFC)       │  │   │  ┌──────────────────┐  │  │
│  │  └────────────────┘  │   │  │ Threat Detection │  │  │
│  └──────────────────────┘   │  └──────────────────┘  │  │
│                              └────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
```

### Key Design Principles

1. **Privilege Separation**: Agent runs read-only; writes happen in a separate job with scoped tokens
2. **Compile-Time Validation**: Most safety checks happen during workflow compilation, not at runtime
3. **Least-Privilege Tokens**: Permissions are computed per-handler — only what's needed is requested
4. **Defense in Depth**: Multiple independent layers (sandbox, firewall, validation, DIFC, threat detection)
5. **Schema-Driven Tools**: MCP tool definitions are statically defined and filtered at compile time
6. **Staged Mode**: Any safe output can be previewed without executing real writes

### Language Split

| Layer | Language | Location |
|-------|----------|----------|
| Compiler, validation, config extraction | Go | `pkg/workflow/` |
| Runtime handlers, validators, sanitizers | JavaScript (CJS) | `actions/setup/js/` |
| Type definitions | TypeScript (.d.ts) | `actions/setup/js/types/` |
| Tool schemas | JSON | `actions/setup/js/safe_outputs_tools.json` |
| Agent output schema | JSON Schema | `schemas/agent-output.json` |

---

## 2. Core Concept: Safe Outputs

Safe outputs are the **only mechanism** through which an AI agent can perform write operations (create issues, PRs, comments, labels, etc.) on GitHub. The agent produces structured JSONL output, which is then validated, sanitized, and executed by dedicated handlers in a separate job.

### How It Works (End-to-End Flow)

```
1. Workflow author declares safe-outputs in frontmatter:
   ---
   safe-outputs:
     create-issue:
       max: 3
       labels: ["bug"]
     add-comment:
       target: triggering
   ---

2. Go compiler:
   a. Extracts config → SafeOutputsConfig struct
   b. Validates config (domains, targets, permissions, etc.)
   c. Computes minimal permissions for the safe-outputs job
   d. Filters MCP tool definitions to only expose enabled tools
   e. Generates GitHub Actions YAML with two jobs:
      - agent job (read-only, sandboxed)
      - safe_outputs job (scoped write token)

3. At runtime, the agent produces JSONL via MCP tool calls:
   {"type": "create_issue", "title": "Bug found", "body": "Details..."}
   {"type": "add_comment", "body": "Analysis complete"}

4. The safe_outputs job:
   a. Loads agent output (JSONL)
   b. Validates each item (type, required fields, max counts, allowed values)
   c. Sanitizes content (mentions, URLs, unicode, commands)
   d. Dispatches to type-specific handlers
   e. Executes GitHub API calls with scoped token
   f. Runs threat detection on outputs
```

### The "noop" Requirement

A critical design detail: the agent **must** call at least one safe-output tool before finishing. If no action is needed, it must call `noop` with an explanation. This prevents silent failures and ensures every run produces auditable output.

```json
{"type": "noop", "message": "No action needed: analyzed 3 files, all tests passing"}
```

### Temporary IDs for Cross-Referencing

Safe outputs support `temporary_id` fields that allow cross-referencing between items in the same batch. For example, creating an issue and immediately linking it as a sub-issue:

```json
{"type": "create_issue", "title": "Parent", "body": "...", "temporary_id": "aw_parent1"}
{"type": "create_issue", "title": "Child", "body": "...", "parent": "aw_parent1"}
```

Format: `aw_` + 3-8 alphanumeric characters (`/^aw_[A-Za-z0-9]{3,8}$/`).

---

## 3. Type System & Schema Design

### Base Interface (TypeScript)

Every safe output item extends a base interface with security metadata:

```typescript
// File: actions/setup/js/types/safe-outputs.d.ts

interface BaseSafeOutputItem {
  /** The type of safe output action */
  type: string;

  /**
   * Secrecy level of the message content.
   * Indicates the confidentiality of the data included in this message
   * (e.g., "public", "internal", "private").
   */
  secrecy?: string;

  /**
   * Integrity level of the message content.
   * Indicates the trustworthiness of the data source for this message
   * (e.g., "low", "medium", "high").
   */
  integrity?: string;
}
```

The `secrecy` and `integrity` fields are the foundation for the DIFC (Decentralized Information Flow Control) system covered in Section 10.

### Supported Output Types (30+)

Each type has a discriminated union via the `type` field:

| Type | Purpose | Key Fields |
|------|---------|------------|
| `create_issue` | Create GitHub issue | `title`, `body`, `labels?`, `parent?`, `temporary_id?` |
| `add_comment` | Comment on issue/PR | `body` |
| `create_pull_request` | Create PR | `title`, `body`, `branch?`, `labels?`, `draft?` |
| `push_to_pull_request_branch` | Push code to PR branch | `message?`, `pull_request_number?` |
| `create_pull_request_review_comment` | Inline PR review comment | `path`, `line`, `body`, `side?` |
| `submit_pull_request_review` | Submit a PR review | (review-specific fields) |
| `add_labels` / `remove_labels` | Manage labels | `labels[]` |
| `close_issue` / `close_pull_request` | Close items | `body`, `issue_number?` |
| `update_issue` / `update_pull_request` | Update items | `status?`, `title?`, `body?` |
| `create_code_scanning_alert` | Security alert | `file`, `line`, `severity`, `message` |
| `autofix_code_scanning_alert` | Fix security alert | `alert_number`, `fix_description`, `fix_code` |
| `create_discussion` | Create discussion | `title`, `body`, `category_id?` |
| `update_project` | Manage project boards | (project-specific fields) |
| `dispatch_workflow` | Trigger another workflow | (dispatch-specific fields) |
| `hide_comment` | Minimize a comment | `comment_id`, `reason?` |
| `link_sub_issue` | Link parent/child issues | `parent_issue_number`, `sub_issue_number` |
| `noop` | No action (logging only) | `message` |
| `missing_tool` | Report missing capability | `tool?`, `reason`, `alternatives?` |

### JSON Schema Validation

The formal schema at `schemas/agent-output.json` uses JSON Schema draft-07 with strict `additionalProperties: false`:

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "type": "object",
  "properties": {
    "items": {
      "type": "array",
      "items": { "$ref": "#/$defs/SafeOutput" }
    },
    "errors": {
      "type": "array",
      "items": { "type": "string" }
    }
  },
  "required": ["items", "errors"],
  "additionalProperties": false,
  "$defs": {
    "SafeOutput": {
      "oneOf": [
        { "$ref": "#/$defs/CreateIssueOutput" },
        { "$ref": "#/$defs/AddCommentOutput" },
        // ... 25+ more types
      ]
    }
  }
}
```

**Key pattern**: `additionalProperties: false` on every type prevents agents from injecting unexpected fields.

### MCP Tool Schemas (Static + Dynamic)

Tool definitions live in `actions/setup/js/safe_outputs_tools.json` (embedded at compile time via `//go:embed`). There are two schema generation strategies:

1. **Static schemas**: 30+ built-in types defined in the JSON file, embedded at compile time
2. **Dynamic schemas**: Custom safe-jobs generate MCP tool schemas programmatically from `SafeJobConfig`

```go
// File: pkg/workflow/safe_outputs_config.go (architecture comment)

// ### Static Schemas (30+ built-in safe output types)
// Defined in: pkg/workflow/js/safe_outputs_tools.json
// - Embedded at compile time via //go:embed directive
// - Contains complete MCP tool definitions with inputSchema
//
// ### Dynamic Schema Generation (custom safe-jobs)
// Implemented in: pkg/workflow/safe_outputs_config_generation.go
// - generateCustomJobToolDefinition() builds MCP tool schemas from SafeJobConfig
// - Converts job input definitions to JSON Schema format
// - Supports type mapping (string, boolean, number, choice/enum)
// - Enforces required fields and additionalProperties: false
```

---

## 4. Configuration Extraction & Parsing

The Go compiler extracts safe-outputs configuration from workflow YAML frontmatter and builds a strongly-typed `SafeOutputsConfig` struct. This is the central data structure that drives everything downstream.

### Frontmatter Format

```yaml
---
safe-outputs:
  create-issue:
    max: 3
    labels: ["bug", "auto"]
    title-prefix: "[Bot]"
    target-repo: "org/other-repo"
    allowed-repos: ["org/repo1", "org/repo2"]
    footer: true
  add-comment:
    max: 5
    target: "triggering"        # or "*" or "123" or "${{ github.event.issue.number }}"
  add-labels:
    max: 10
    allowed: ["bug", "feature", "docs"]
  create-pull-request:
    max: 1
    title-prefix: "[Auto]"
    labels: ["automated"]
    draft: true
    fallback-as-issue: true     # Create issue instead if branch is protected
    footer: true
  close-issue:
    required-labels: ["auto-closable"]
    required-title-prefix: "[Bot]"
    target: "triggering"
  allowed-domains:              # Additional network domains for safe outputs
    - "*.github.com"
    - "api.example.com"
    - "python"                  # Ecosystem identifier (expands to known domains)
  staged: false                 # Global staged mode (dry-run)
  github-token: "${{ secrets.CUSTOM_TOKEN }}"
  max-patch-size: 500000
---
```

### Go Config Struct (Simplified)

```go
// File: pkg/workflow/safe_outputs_config.go

type SafeOutputsConfig struct {
    // Per-handler configs (nil = not enabled)
    CreateIssues                    *CreateIssuesConfig
    CreateDiscussions               *CreateDiscussionsConfig
    AddComments                     *AddCommentsConfig
    CreatePullRequests              *CreatePullRequestsConfig
    AddLabels                       *AddLabelsConfig
    RemoveLabels                    *RemoveLabelsConfig
    CloseIssues                     *CloseIssuesConfig
    UpdateIssues                    *UpdateIssuesConfig
    PushToPullRequestBranch         *PushToPullRequestBranchConfig
    CreateCodeScanningAlerts        *CreateCodeScanningAlertsConfig
    // ... 20+ more handler configs

    // Cross-cutting configs
    AllowedDomains         []string
    AllowGitHubReferences  []string
    Staged                 bool              // Global staged mode
    Env                    map[string]string  // Extra env vars
    GitHubToken            string
    MaximumPatchSize       int

    // Auto-injected types (always enabled)
    NoOp        *NoOpConfig
    MissingTool *MissingToolConfig
    MissingData *MissingDataConfig

    // Custom extensibility
    Jobs    map[string]*SafeJobConfig
    Scripts map[string]*SafeScriptConfig
    Actions map[string]*SafeActionConfig

    // Threat detection
    ThreatDetection *ThreatDetectionConfig

    // Metadata
    AutoInjectedCreateIssue bool
    IDToken                 *string
}
```

### Key Extraction Patterns

**1. Each handler type has a dedicated parser:**
```go
func (c *Compiler) extractSafeOutputsConfig(frontmatter map[string]any) *SafeOutputsConfig {
    if output, exists := frontmatter["safe-outputs"]; exists {
        if outputMap, ok := output.(map[string]any); ok {
            config := &SafeOutputsConfig{}

            // Each handler has its own parser
            issuesConfig := c.parseIssuesConfig(outputMap)
            if issuesConfig != nil {
                config.CreateIssues = issuesConfig
            }
            // ... repeat for each handler type
        }
    }
}
```

**2. Auto-enabled builtin types:** `noop`, `missing-tool`, and `missing-data` are automatically enabled when any safe-outputs section exists, unless explicitly disabled. This ensures every run has a fallback.

```go
// Enable noop by default as fallback for transparency
if _, exists := outputMap["noop"]; !exists {
    config.NoOp = &NoOpConfig{}
    config.NoOp.Max = defaultIntStr(1)
}
```

**3. Auto-injected create-issue:** If safe-outputs is configured but has no "real" (non-builtin) output types, the compiler auto-injects a `create-issue` handler using the workflow ID as label and title prefix.

```go
func applyDefaultCreateIssue(workflowData *WorkflowData) {
    if hasNonBuiltinSafeOutputsEnabled(workflowData.SafeOutputs) {
        return // has real outputs, no need to inject
    }
    workflowData.SafeOutputs.CreateIssues = &CreateIssuesConfig{
        BaseSafeOutputConfig: BaseSafeOutputConfig{Max: defaultIntStr(1)},
        Labels:               []string{workflowID},
        TitlePrefix:          fmt.Sprintf("[%s]", workflowID),
    }
    workflowData.SafeOutputs.AutoInjectedCreateIssue = true
}
```

### Per-Handler Configuration Options

Each handler config type extends a base config:

```typescript
// File: actions/setup/js/types/safe-outputs-config.d.ts

interface SafeOutputConfig {
  type: string;
  max?: number;           // Maximum number of outputs of this type
  min?: number;           // Minimum required outputs
  "github-token"?: string; // Custom token override
}
```

Common configuration fields across handler types:

| Field | Purpose | Example |
|-------|---------|---------|
| `max` | Max outputs of this type per run | `max: 3` |
| `target` | Which item to operate on | `"triggering"`, `"*"`, `"123"`, `"${{ expr }}"` |
| `target-repo` | Cross-repo targeting | `"org/other-repo"` |
| `allowed-repos` | Repos the agent may target | `["org/repo1"]` |
| `title-prefix` | Required prefix on titles | `"[Bot]"` |
| `labels` | Labels to auto-apply | `["automated"]` |
| `required-labels` | Labels required on target | `["auto-closable"]` |
| `allowed` | Allowed values (labels, milestones) | `["bug", "feature"]` |
| `footer` | Append AI-generated attribution | `true` |
| `staged` | Per-handler dry-run mode | `true` |
| `github-token` | Custom token for this handler | `"${{ secrets.X }}"` |

### Target Resolution

The `target` field controls which issue/PR/discussion the action operates on:

| Value | Behavior |
|-------|----------|
| `""` or `"triggering"` | Uses the triggering issue/PR from the event |
| `"*"` | Any item — the agent specifies via `issue_number` field |
| `"123"` | Specific item number |
| `"${{ github.event.issue.number }}"` | GitHub Actions expression |

Validation ensures only these forms are accepted:

```go
func validateTargetValue(configName, target string) error {
    if target == "" || target == "triggering" { return nil }
    if target == "*" { return nil }
    if isGitHubExpression(target) { return nil }
    if stringutil.IsPositiveInteger(target) { return nil }
    return fmt.Errorf("invalid target value for %s: %q\n\nValid target values are:...", ...)
}
```

---

## 5. Least-Privilege Permission Computation

One of the most important safety mechanisms: the safe-outputs job **only requests the GitHub token permissions it actually needs** based on which handlers are configured.

### How It Works

```go
// File: pkg/workflow/safe_outputs_permissions.go

func ComputePermissionsForSafeOutputs(safeOutputs *SafeOutputsConfig) *Permissions {
    permissions := NewPermissions()

    // Each handler adds only what it needs
    if safeOutputs.CreateIssues != nil && !isHandlerStaged(...) {
        permissions.Merge(NewPermissionsContentsReadIssuesWrite())
    }
    if safeOutputs.CreatePullRequests != nil && !isHandlerStaged(...) {
        if getFallbackAsIssue(safeOutputs.CreatePullRequests) {
            permissions.Merge(NewPermissionsContentsWriteIssuesWritePRWrite())
        } else {
            permissions.Merge(NewPermissionsContentsWritePRWrite())
        }
    }
    // ... more handlers

    // All handlers staged → explicit empty permissions
    if len(permissions.permissions) == 0 {
        return NewPermissionsEmpty() // renders "permissions: {}"
    }
    return permissions
}
```

### Permission Mapping Table

| Handler | Permissions Required |
|---------|---------------------|
| `create-issue`, `close-issue`, `update-issue` | `contents: read`, `issues: write` |
| `create-discussion`, `close-discussion` | `contents: read`, `issues: write`, `discussions: write` |
| `add-comment` | `contents: read`, `issues: write` (+ `pull-requests: write` if PR context) |
| `create-pull-request` | `contents: write`, `pull-requests: write` |
| `create-pull-request` + `fallback-as-issue` | `contents: write`, `issues: write`, `pull-requests: write` |
| `push-to-pull-request-branch` | `contents: write`, `pull-requests: write` |
| `add-labels`, `remove-labels` | `contents: read`, `issues: write`, `pull-requests: write` |
| `create-code-scanning-alert` | `contents: read`, `security-events: write` |
| `autofix-code-scanning-alert` | `contents: read`, `security-events: write`, `actions: read` |
| `dispatch-workflow` | `actions: write` |
| `update-project`, `create-project` | `contents: read`, `projects: write` |
| `upload-asset`, `update-release` | `contents: write` |
| All handlers staged | `permissions: {}` (explicit empty) |

### Staged Handler Skipping

Staged handlers (dry-run) are **skipped** during permission computation because they don't make real API calls:

```go
func isHandlerStaged(globalStaged, handlerStaged bool) bool {
    return globalStaged || handlerStaged
}

// In ComputePermissionsForSafeOutputs:
if safeOutputs.CreateIssues != nil && !isHandlerStaged(safeOutputs.Staged, safeOutputs.CreateIssues.Staged) {
    permissions.Merge(NewPermissionsContentsReadIssuesWrite())
}
```

This means a workflow in staged mode gets `permissions: {}` — zero write access.

### OIDC Token Auto-Detection

The system auto-detects when OIDC vault actions (AWS, Azure, GCP, HashiCorp Vault) are used in custom steps and adds `id-token: write`:

```go
var oidcVaultActions = []string{
    "aws-actions/configure-aws-credentials",
    "azure/login",
    "google-github-actions/auth",
    "hashicorp/vault-action",
    "cyberark/conjur-action",
}

// Auto-detection in permission computation:
if stepsRequireIDToken(safeOutputs.Steps) {
    permissions.Set(PermissionIdToken, PermissionWrite)
}
```

### Convenience: Config-from-Keys

For the interactive wizard and external callers, there's a helper to build a minimal config from key names:

```go
func SafeOutputsConfigFromKeys(keys []string) *SafeOutputsConfig {
    config := &SafeOutputsConfig{}
    for _, key := range keys {
        switch key {
        case "create-issue":
            config.CreateIssues = &CreateIssuesConfig{}
        case "add-comment":
            config.AddComments = &AddCommentsConfig{}
        // ... 30+ cases
        }
    }
    return config
}
```

---

## 6. Tool Filtering & MCP Integration

The agent interacts with safe outputs through **MCP (Model Context Protocol) tools**. The compiler filters the full set of tool definitions to only expose tools the workflow has enabled.

### Architecture

```
┌─────────────────────────────────┐
│ safe_outputs_tools.json (static)│  30+ built-in tool definitions
│ Embedded via //go:embed          │  with inputSchema for each
└──────────────┬──────────────────┘
               │
               ▼
┌─────────────────────────────────┐
│ generateFilteredToolsJSON()     │  Filters to only enabled tools
│ (Go compile-time)               │  Enhances descriptions with config
│                                 │  Adds repo params if needed
└──────────────┬──────────────────┘
               │
               ├── + Custom job tool definitions (dynamic)
               ├── + Custom script tool definitions (dynamic)
               ├── + Custom action tool definitions (dynamic)
               │
               ▼
┌─────────────────────────────────┐
│ MCP Gateway                     │  Exposes filtered tools to agent
│ (runtime)                       │  Applies guard policies + DIFC
└─────────────────────────────────┘
```

### Two Generation Strategies

**1. Legacy (inline):** `generateFilteredToolsJSON()` — loads embedded JSON, filters, returns full JSON inlined into compiled YAML.

**2. New (meta-based):** `generateToolsMetaJSON()` — generates a small "meta" JSON with description suffixes, repo params, and dynamic tools. At runtime, `generate_safe_outputs_tools.cjs` merges meta with the source JSON. This avoids inlining large JSON into the workflow YAML.

### Filtering Logic

```go
func generateFilteredToolsJSON(data *WorkflowData, markdownPath string) (string, error) {
    allToolsJSON := GetSafeOutputsToolsJSON()  // Embedded JSON
    var allTools []map[string]any
    json.Unmarshal([]byte(allToolsJSON), &allTools)

    // Build set of enabled tools from config
    enabledTools := make(map[string]bool)
    if data.SafeOutputs.CreateIssues != nil {
        enabledTools["create_issue"] = true
    }
    // ... for each handler type

    // Filter and enhance
    var filteredTools []map[string]any
    for _, tool := range allTools {
        toolName := tool["name"].(string)
        if enabledTools[toolName] {
            enhancedTool := maps.Clone(tool)
            enhancedTool["description"] = enhanceToolDescription(toolName, description, config)
            addRepoParameterIfNeeded(enhancedTool, toolName, config)
            filteredTools = append(filteredTools, enhancedTool)
        }
    }

    // Safety check: verify all registered tools exist in static JSON
    checkAllEnabledToolsPresent(enabledTools, filteredTools)

    // Add dynamic tools (custom jobs, scripts, actions)
    for _, jobName := range sortedJobNames {
        customTool := generateCustomJobToolDefinition(normalizedName, jobConfig)
        filteredTools = append(filteredTools, customTool)
    }

    return json.Marshal(filteredTools)
}
```

### Description Enhancement

Tool descriptions are dynamically enhanced with configuration details so the agent knows constraints:

```go
func enhanceToolDescription(toolName, description string, config *SafeOutputsConfig) string {
    // Example: adds "Target: triggering issue" or "Max: 3" to description
    // so the LLM sees constraints directly in the tool schema
}
```

### Repo Parameter Injection

When `allowed-repos` is configured, the tool's `inputSchema` gets an additional `repo` parameter so the agent can specify cross-repo targets:

```go
func addRepoParameterIfNeeded(tool map[string]any, toolName string, config *SafeOutputsConfig) {
    // If this handler has allowed-repos, add "repo" to inputSchema.properties
}
```

### Custom Tool Generation

Custom jobs, scripts, and actions generate MCP tool definitions programmatically:

```go
func generateCustomJobToolDefinition(name string, config *SafeJobConfig) map[string]any {
    // Builds a complete MCP tool definition:
    // - name: normalized identifier
    // - description: from config
    // - inputSchema: built from job input definitions
    //   - type mapping: string, boolean, number, choice→enum
    //   - required fields enforced
    //   - additionalProperties: false
}
```

### State Inspection via Reflection

The system uses Go reflection to check which handlers are enabled without maintaining a large switch statement:

```go
var safeOutputFieldMapping = map[string]string{
    "CreateIssues":       "create_issue",
    "AddComments":        "add_comment",
    "CreatePullRequests": "create_pull_request",
    // ... 35+ mappings
}

func hasAnySafeOutputEnabled(safeOutputs *SafeOutputsConfig) bool {
    val := reflect.ValueOf(safeOutputs).Elem()
    for fieldName := range safeOutputFieldMapping {
        field := val.FieldByName(fieldName)
        if field.IsValid() && !field.IsNil() {
            return true
        }
    }
    return false
}
```

This also powers the distinction between "builtin" types (`noop`, `missing-data`, `missing-tool`) and "real" output types via `hasNonBuiltinSafeOutputsEnabled()`.

---

## 7. Validation Pipeline

The validation system is split across 20+ focused files, each responsible for a specific domain. Validation happens primarily at **compile time** (when the Go compiler processes the workflow markdown), preventing invalid configurations from ever reaching GitHub Actions.

### Validation Architecture

```
pkg/workflow/
├── validation.go                        # Architecture docs only (package-level)
├── safe_outputs_validation.go           # Domain & target validation
├── safe_outputs_validation_config.go    # Config-level validation
├── template_injection_validation.go     # Shell injection detection
├── expression_safety_validation.go      # Expression allowlist
├── dangerous_permissions_validation.go  # Write permission enforcement
├── strict_mode_validation.go            # Production hardening
├── strict_mode_permissions_validation.go
├── strict_mode_env_validation.go
├── markdown_security_scanner.go         # Malicious content detection
├── firewall_validation.go               # AWF config validation
├── sandbox_validation.go                # Sandbox config validation
├── network_firewall_validation.go       # Network rules validation
├── agent_validation.go                  # Agent config validation
├── call_workflow_validation.go          # Reusable workflow validation
├── imported_steps_validation.go         # Import validation
├── template_validation.go               # Template structure validation
├── compiler_filters_validation.go       # Filter validation
├── schema_validation.go                 # JSON schema validation
├── runtime_validation.go                # Runtime packages/containers
├── engine_validation.go                 # AI engine config validation
├── mcp_config_validation.go             # MCP server config validation
├── bundler_safety_validation.go         # JS bundle safety checks
└── bundler_script_validation.go         # JS script content checks
```

### Error Collector Pattern

Validations use an `ErrorCollector` that supports both "fail-fast" (stop on first error) and "collect-all" (gather all errors) modes:

```go
collector := NewErrorCollector(c.failFast)

if err := c.validateStrictPermissions(frontmatter); err != nil {
    if returnErr := collector.Add(err); returnErr != nil {
        return returnErr // Fail-fast mode: stop immediately
    }
}
// ... more validations

return collector.FormattedError("strict mode") // Collect-all: return all errors
```

### ValidationError Pattern

Validation errors include actionable fix suggestions:

```go
func NewValidationError(field, value, message, suggestion string) *ValidationError {
    return &ValidationError{
        Field:      field,
        Value:      value,
        Message:    message,
        Suggestion: suggestion,
    }
}

// Example usage:
return NewValidationError(
    "domain", domain,
    "domain pattern contains multiple wildcards, only one wildcard at the start is allowed",
    "Use a single wildcard at the start of the domain. Examples:\n  - '*.example.com' ✓\n  - '*.*.example.com' ✗",
)
```

### Domain Validation

Network allowed domains are validated at compile time with support for:
- Plain domains: `github.com`, `api.github.com`
- Wildcard domains: `*.github.com`
- Protocol-specific: `https://api.github.com`
- Ecosystem identifiers: `"python"`, `"node"`, `"dev-tools"` (expand to known domain sets)

```go
var domainPattern = regexp.MustCompile(
    `^(\*\.)?[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?` +
    `(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$`)

func isEcosystemIdentifier(domain string) bool {
    return isEcosystemIdentifierPattern.MatchString(domain) // ^[a-z][a-z0-9-]*$
}
```

Invalid patterns caught: multiple wildcards, wildcard not at start, trailing dots, consecutive dots, invalid characters, invalid protocols.

### Fuzz Testing

Security-critical validators have fuzz tests to catch edge cases:

```
security_fuzz_test.go                    # General security fuzzing
template_injection_validation_fuzz_test.go
expression_parser_fuzz_test.go
sanitize_incoming_text_fuzz_test.go
sanitize_output_fuzz_test.go
markdown_code_region_balancer_fuzz_test.go
```

---

## 8. Handler Manager & Message Dispatch

At runtime, the **Handler Manager** (`safe_output_handler_manager.cjs`) orchestrates the processing of all agent output messages. It implements a sophisticated dispatch pipeline with dependency resolution, fail-fast behavior, and deferred execution.

### Handler Architecture

```
┌────────────────────────────────────────────────────────┐
│               Handler Manager (orchestrator)            │
│                                                         │
│  1. Load config from GH_AW_SAFE_OUTPUTS_HANDLER_CONFIG │
│  2. Initialize handlers (factory pattern)               │
│  3. Process messages in order                           │
│  4. Resolve temporary IDs across messages               │
│  5. Generate summaries and manifests                    │
└──────────────────────┬─────────────────────────────────┘
                       │
        ┌──────────────┼──────────────────┐
        ▼              ▼                  ▼
┌──────────────┐ ┌──────────────┐ ┌──────────────┐
│ Built-in     │ │ Custom Script│ │ Custom Action │
│ Handlers     │ │ Handlers     │ │ Handlers      │
│ (35+ .cjs)   │ │ (.cjs files) │ │ (uses: steps) │
└──────────────┘ └──────────────┘ └──────────────┘
```

### Handler Map

Each safe output type maps to a dedicated handler module:

```javascript
const HANDLER_MAP = {
  create_issue:                        "./create_issue.cjs",
  add_comment:                         "./add_comment.cjs",
  create_pull_request:                 "./create_pull_request.cjs",
  push_to_pull_request_branch:         "./push_to_pull_request_branch.cjs",
  create_pull_request_review_comment:  "./create_pr_review_comment.cjs",
  add_labels:                          "./add_labels.cjs",
  close_issue:                         "./close_issue.cjs",
  create_code_scanning_alert:          "./create_code_scanning_alert.cjs",
  // ... 30+ more
};
```

### Factory Pattern

Each handler module exports a `main()` factory that receives config and returns a message handler function:

```javascript
// Handler module pattern:
module.exports = {
  async main(config) {
    // Initialize with config (target, max, allowed, etc.)
    // Return a message handler function
    return async function handleMessage(message, resolvedTemporaryIds, temporaryIdMap) {
      // Validate, sanitize, and execute the GitHub API call
      return { success: true, number: 42, url: "..." };
    };
  }
};
```

### Message Processing Pipeline

```
For each message in agent output (in order):
│
├─ No type? → Skip with warning
│
├─ Code-push failure earlier? → Cancel non-code-push messages
│
├─ Handler found?
│  ├─ Yes → Process message:
│  │        1. Resolve temporary ID references
│  │        2. Call handler with message + resolved IDs
│  │        3. If success → record temp ID mapping if present
│  │        4. If failure → track code-push failures
│  │        5. If deferred → queue for retry
│  │        6. Log to manifest
│  │
│  ├─ Standalone type? → Skip (handled by dedicated step)
│  │   (assign_to_agent, create_agent_session, upload_asset)
│  │
│  ├─ Custom job type? → Skip (handled by custom job step)
│  │
│  └─ Unknown → Warn user
│
└─ After first pass:
   ├─ Retry deferred messages (temp IDs now resolved)
   └─ Generate summaries and emit action outputs
```

### Code-Push Fail-Fast

If a code-push operation (`push_to_pull_request_branch` or `create_pull_request`) fails, **all subsequent non-code-push messages are cancelled**:

```javascript
const CODE_PUSH_TYPES = new Set([
  "push_to_pull_request_branch",
  "create_pull_request"
]);

// During processing:
if (codePushFailures.length > 0 && !CODE_PUSH_TYPES.has(messageType)) {
  const cancelReason = `Cancelled: code push failed (${codePushFailures[0].error})`;
  results.push({ type: messageType, success: false, cancelled: true, reason: cancelReason });
  continue;
}
```

### Fallback-to-Issue

When `create_pull_request` fails due to protected branch changes, it can fall back to creating a review issue. Subsequent `add_comment` messages get a correction note prepended:

```javascript
if (messageType === "add_comment" && codePushFallbackInfo) {
  const fallbackNote = `> [!NOTE]\n> The pull request was not created — a fallback review issue was created instead`;
  effectiveMessage = { ...message, body: fallbackNote + message.body };
}
```

### Temporary ID Resolution

Messages can reference temporary IDs from earlier messages. The handler manager maintains a shared map and resolves references as items are created:

```javascript
const temporaryIdMap = new Map();

// After successful create:
if (result.temporaryId && result.repo && result.number) {
  temporaryIdMap.set(normalizeTemporaryId(result.temporaryId), {
    repo: result.repo,
    number: result.number,
  });
}

// Before processing each message:
const resolvedTemporaryIds = Object.fromEntries(temporaryIdMap);
// Passed to handler which calls replaceTemporaryIdReferences()
```

### Manifest Tracking

Every successful operation is logged to a manifest for audit purposes:

```javascript
const createdItem = extractCreatedItemFromResult(messageType, result);
if (createdItem && onItemCreated) {
  onItemCreated(createdItem); // Logs: 📝 Manifest: logged create_issue → https://...
}
```

---

## 9. Content Sanitization

All content produced by the agent is sanitized before being written to GitHub. The sanitization pipeline is layered: a core module handles universal sanitization, and a full module adds mention filtering.

### Sanitization Pipeline

```
Agent Output (raw text)
  │
  ├── 1. hardenUnicodeText()         → Normalize unicode representation
  ├── 2. removeXmlComments()         → Strip <!-- ... --> comments
  ├── 3. convertXmlTags()            → Convert <tag> to safe format
  ├── 4. sanitizeUrlProtocols()      → Redact non-https URLs (ftp, data, javascript, etc.)
  ├── 5. sanitizeUrlDomains()        → Redact URLs to non-allowed domains
  ├── 6. neutralizeCommands()        → Neutralize shell commands
  ├── 7. neutralizeGitHubReferences()→ Neutralize @mentions (selective)
  ├── 8. neutralizeBotTriggers()     → Neutralize bot trigger patterns
  ├── 9. balanceCodeRegions()        → Ensure code blocks are properly closed
  ├── 10. applyTruncation()          → Enforce max length (default 524288)
  │
  └── Sanitized Output
```

### Key Sanitization Functions

**URL Protocol Sanitization:**
Non-HTTPS protocols are redacted to prevent protocol-based attacks:

```javascript
function sanitizeUrlProtocols(s) {
  // Matches: http://, ftp://, file://, ssh://, git://, data:, javascript:, etc.
  return s.replace(/((?:http|ftp|file|ssh|git):\/\/([\w.-]*)...)/gi,
    (match, _fullMatch, domain) => {
      addRedactedDomain(domainLower);
      return sanitized ? `(${sanitized}/redacted)` : "(redacted)";
    }
  );
}
```

**URL Domain Filtering:**
HTTPS URLs to non-allowed domains are redacted. Allowed domains come from:
- Default set: `github.com`, `github.io`, `githubusercontent.com`, etc.
- `GH_AW_ALLOWED_DOMAINS` env var
- GitHub Enterprise domains extracted from `GITHUB_SERVER_URL` / `GITHUB_API_URL`

```javascript
function buildAllowedDomains() {
  const defaultAllowedDomains = [
    "github.com", "github.io", "githubusercontent.com",
    "githubassets.com", "github.dev", "codespaces.new"
  ];
  // + env var domains + GitHub Enterprise domains
  return [...new Set(allDomains)];
}
```

**Mention Neutralization:**
`@mentions` are neutralized to prevent unintended notifications, unless they're in the `allowedAliases` list:

```javascript
function sanitizeContent(content, options) {
  const allowedAliasesLowercase = (options.allowedAliases || [])
    .map(alias => alias.toLowerCase());

  if (allowedAliasesLowercase.length === 0) {
    return sanitizeContentCore(content, maxLength, maxBotMentions);
    // neutralizes ALL @mentions
  }
  // Otherwise: selective mention filtering
}
```

**Bot Trigger Neutralization:**
Patterns that trigger bots (like `@dependabot rebase`) are detected and neutralized when they exceed a threshold (`maxBotMentions`, default 10).

**Redacted Domains Logging:**
All redacted domains are tracked and written to `/tmp/gh-aw/redacted-urls.log` for audit purposes.

### Label Sanitization

Labels have their own sanitization pipeline:

```javascript
function validateLabels(labels, allowedLabels, maxCount, blockedPatterns) {
  // 1. Reject removal attempts (labels starting with '-')
  // 2. Filter blocked labels via glob patterns (e.g., "~*", "*[bot]")
  // 3. Filter against allowed list (if configured)
  // 4. Sanitize and deduplicate
  // 5. Truncate to 64 chars per label
  // 6. Apply max count limit
}
```

### Content Length Limits

| Field | Default Max Length |
|-------|-------------------|
| Body content | 524,288 chars (~512KB) |
| Label name | 64 chars |
| Title | Trimmed, must be non-empty |

### GitHub Reference Sanitization

Cross-repo references (like `org/repo#123`) are neutralized unless they match `allowed-github-references`:

```javascript
function buildAllowedGitHubReferences() {
  // Built from GH_AW_ALLOWED_GITHUB_REFERENCES env var
  // Only allows references to repos explicitly listed
}
```

---

## 10. Integrity & Secrecy (DIFC)

The system implements **Decentralized Information Flow Control (DIFC)** through integrity and secrecy labels on safe output messages. This prevents agents from acting on untrusted data or leaking confidential information.

### How DIFC Works

Every safe output item can carry `secrecy` and `integrity` metadata:

```typescript
interface BaseSafeOutputItem {
  type: string;
  secrecy?: string;    // "public", "internal", "private"
  integrity?: string;  // "low", "medium", "high"
}
```

The **MCP Gateway** enforces DIFC policies by filtering tool calls that access resources not meeting required levels. When a tool call is blocked, a `DIFC_FILTERED` event is logged.

### DIFC_FILTERED Events

The gateway logs DIFC filtering events as JSONL:

```json
{
  "type": "DIFC_FILTERED",
  "tool_name": "add_comment",
  "html_url": "https://github.com/org/repo/issues/42",
  "number": 42,
  "description": "Issue #42",
  "reason": "Resource integrity level does not meet workflow requirements",
  "author": "untrusted-user",
  "association": "NONE"
}
```

### User-Facing Display

Filtered events are displayed in the AI-generated footer as a collapsible note:

```javascript
// File: actions/setup/js/gateway_difc_filtered.cjs

function generateDifcFilteredSection(filteredEvents) {
  let section = "\n\n> [!NOTE]\n";
  section += `> <details>\n`;
  section += `> <summary>🔒 Integrity filtering filtered ${count} ${itemWord}</summary>\n`;
  section += `> Integrity filtering activated and filtered the following items.\n`;
  section += `> This happens when a tool call accesses a resource that does not ` +
             `meet the required integrity or secrecy level.\n`;

  for (const event of visibleEvents) {
    section += `> - ${reference} (${tool}: ${reason})\n`;
  }
  // Max 16 visible, remainder summarized
}
```

### Secrecy/Integrity in Summaries

When safe output messages include secrecy or integrity metadata, it's displayed in step summaries:

```javascript
// File: actions/setup/js/safe_output_summary.cjs

if (message.secrecy !== undefined && message.secrecy !== null) {
  summary += `**Secrecy:** \`${message.secrecy}\`\n\n`;
}
if (message.integrity !== undefined && message.integrity !== null) {
  summary += `**Integrity:** \`${message.integrity}\`\n\n`;
}
```

### Guard Policies (DIFC Configuration)

Guard policies configure how DIFC is enforced at the MCP gateway level. See [Section 21](#21-guard-policies) for details.

---

## 11. Sandbox & Network Firewall

The sandbox system provides **network egress control** to prevent agents from making unauthorized outbound connections. Two sandbox types are supported.

### Sandbox Types

| Type | Name | Description |
|------|------|-------------|
| `awf` | Agent Workflow Firewall | Proxy-based firewall (default for Copilot engine) |
| `srt` | Sandbox Runtime | Anthropic's container sandbox |

### Configuration

```yaml
---
# New format (recommended)
sandbox:
  agent: awf              # or "srt" or false (disable)
    # AWF-specific:
    command: custom-cmd    # Override installation command
    args: ["--flag"]       # Additional CLI arguments
    env: { KEY: "value" }  # Environment variables
    mounts: ["src:dest:ro"]# Container mounts
    memory: "4g"           # Memory limit

# Network controls
network:
  allowed:
    - "github.com"
    - "*.npmjs.org"
    - "python"             # Ecosystem identifier
    - "*"                  # Allow all (disables firewall for Copilot)

  firewall:                # AWF-specific (deprecated, use sandbox.agent)
    enabled: true
    version: "latest"
    log_level: "info"
    ssl_bump: true
    allow_urls:
      - "https://github.com/githubnext/*"
---
```

### Firewall Enable Logic

```go
// File: pkg/workflow/firewall.go

func isFirewallEnabled(workflowData *WorkflowData) bool {
    // 1. Explicit disable: sandbox.agent: false
    if isFirewallDisabledBySandboxAgent(workflowData) { return false }

    // 2. Explicit firewall config
    if workflowData.NetworkPermissions.Firewall != nil {
        return workflowData.NetworkPermissions.Firewall.Enabled
    }

    // 3. Implicit via sandbox config
    if isSandboxEnabled(workflowData.SandboxConfig, workflowData.NetworkPermissions) {
        return true
    }

    return false
}
```

### Default Firewall for Copilot

The firewall is enabled by default for Copilot and Codex engines when network restrictions exist, **unless**:
- `allowed` contains `"*"` (unrestricted network)
- `sandbox.agent` is explicitly `false`
- SRT sandbox is configured (mutually exclusive with AWF)

```go
func enableFirewallByDefaultForCopilot(engineID string, network *NetworkPermissions, sandbox *SandboxConfig) {
    // Auto-enables AWF when Copilot/Codex engine has network restrictions
}
```

### SRT (Sandbox Runtime) Configuration

The SRT sandbox provides filesystem and network isolation:

```go
type SandboxRuntimeConfig struct {
    Network    *SRTNetworkConfig    // Allowed/blocked domains, unix sockets
    Filesystem *SRTFilesystemConfig // Read/write deny lists
    IgnoreViolations map[string][]string
    EnableWeakerNestedSandbox bool
}

type SRTNetworkConfig struct {
    AllowedDomains      []string  // Domains the agent can reach
    BlockedDomains      []string  // Explicitly blocked domains
    AllowUnixSockets    []string  // Allowed unix socket paths
    AllowLocalBinding   bool      // Allow binding to localhost
    AllowAllUnixSockets bool
}

type SRTFilesystemConfig struct {
    DenyRead   []string  // Paths the agent cannot read
    AllowWrite []string  // Paths the agent can write to
    DenyWrite  []string  // Paths the agent cannot write to
}
```

### Blocked Domains

The system maintains lists of blocked domains (tested in `firewall_blocked_domains_test.go` and `domains_blocked_test.go`) to prevent agents from accessing known-dangerous endpoints.

---

## 12. Template Injection Prevention

Template injection is a critical vulnerability in GitHub Actions where user-controlled data flows directly into shell commands via `${{ }}` expressions.

### The Vulnerability

```yaml
# UNSAFE: User input directly in shell command
- run: echo "${{ github.event.issue.title }}"
  # If title is: "; rm -rf / #
  # Shell executes: echo ""; rm -rf / #"
```

### The Fix

```yaml
# SAFE: Use environment variables
- env:
    TITLE: "${{ github.event.issue.title }}"
  run: echo "$TITLE"
  # Shell variable is properly quoted, no injection possible
```

### Detection Implementation

```go
// File: pkg/workflow/template_injection_validation.go

// Matches ${{ ... }} expressions
var inlineExpressionRegex = regexp.MustCompile(`\$\{\{[^}]+\}\}`)

// Matches high-risk contexts (user-controlled data)
var unsafeContextRegex = regexp.MustCompile(
    `\$\{\{\s*(github\.event\.|steps\.[^}]+\.outputs\.|inputs\.)[^}]+\}\}`)

func validateNoTemplateInjection(yamlContent string) error {
    var workflow map[string]any
    yaml.Unmarshal([]byte(yamlContent), &workflow)

    runBlocks := extractRunBlocks(workflow)

    for _, runContent := range runBlocks {
        if !inlineExpressionRegex.MatchString(runContent) {
            continue
        }

        // Remove heredoc content (safely contains expressions)
        contentWithoutHeredocs := removeHeredocContent(runContent)

        expressions := inlineExpressionRegex.FindAllString(contentWithoutHeredocs, -1)
        for _, expr := range expressions {
            if unsafeContextRegex.MatchString(expr) {
                violations = append(violations, TemplateInjectionViolation{
                    Expression: expr,
                    Snippet:    extractRunSnippet(contentWithoutHeredocs, expr),
                    Context:    detectExpressionContext(expr),
                })
            }
        }
    }
}
```

### High-Risk Contexts Detected

| Context | Example | Risk |
|---------|---------|------|
| `github.event.*` | `github.event.issue.title` | User-controlled event data |
| `steps.*.outputs.*` | `steps.foo.outputs.bar` | Output from previous steps |
| `inputs.*` | `inputs.user_data` | Workflow dispatch inputs |

### Heredoc Exception

Expressions inside heredocs (`<< 'EOF' ... EOF`) are **safe** because they're written to files, not executed in shell. The validator strips heredoc content before scanning:

```go
contentWithoutHeredocs := removeHeredocContent(runContent)
```

### Fuzz Testing

Template injection detection is fuzz-tested (`template_injection_validation_fuzz_test.go`) to ensure edge cases are caught.

---

## 13. Markdown Security Scanner

When workflows are imported from external sources (via `gh aw add` or `gh aw trial`), the content is scanned for malicious patterns. This is a **hard blocker** — no override is available.

### Threat Categories

```go
// File: pkg/workflow/markdown_security_scanner.go

const (
    CategoryUnicodeAbuse       = "unicode-abuse"       // Zero-width chars, bidi overrides
    CategoryHiddenContent      = "hidden-content"      // HTML comments, hidden spans, CSS hiding
    CategoryObfuscatedLinks    = "obfuscated-links"    // Data URIs, mismatched links
    CategoryHTMLAbuse          = "html-abuse"          // Script/iframe/object/embed, event handlers
    CategoryEmbeddedFiles      = "embedded-files"      // SVG with scripts, data-URI payloads
    CategorySocialEngineering  = "social-engineering"  // Misleading formatting
)
```

### Scan Pipeline

```go
func ScanMarkdownSecurity(content string) []SecurityFinding {
    // Strip YAML frontmatter (only scan markdown body)
    markdownBody, lineOffset := stripFrontmatter(content)

    var findings []SecurityFinding

    findings = append(findings, scanUnicodeAbuse(markdownBody)...)
    findings = append(findings, scanHiddenContent(markdownBody)...)
    findings = append(findings, scanObfuscatedLinks(markdownBody)...)
    findings = append(findings, scanHTMLAbuse(markdownBody)...)
    findings = append(findings, scanEmbeddedFiles(markdownBody)...)
    findings = append(findings, scanSocialEngineering(markdownBody)...)

    // Adjust line numbers for stripped frontmatter
    for i := range findings {
        if findings[i].Line > 0 {
            findings[i].Line += lineOffset
        }
    }
    return findings
}
```

### What Each Scanner Detects

| Scanner | Detects |
|---------|---------|
| `scanUnicodeAbuse` | Zero-width characters (U+200B, U+FEFF), bidirectional overrides (U+202A-U+202E), control characters |
| `scanHiddenContent` | HTML comments with suspicious payloads, `<span style="display:none">`, CSS `visibility:hidden` |
| `scanObfuscatedLinks` | `data:` URIs, mismatched link text vs URL (e.g., `[github.com](evil.com)`), percent-encoded URLs |
| `scanHTMLAbuse` | `<script>`, `<iframe>`, `<object>`, `<embed>` tags, `on*` event handlers (`onclick`, `onerror`, etc.) |
| `scanEmbeddedFiles` | SVG files with embedded `<script>`, data-URI image payloads with executable content |
| `scanSocialEngineering` | Misleading formatting patterns, disguised commands, deceptive markdown |

### Security Finding Structure

```go
type SecurityFinding struct {
    Category    SecurityFindingCategory
    Description string
    Line        int    // 1-based line number (adjusted for frontmatter)
    Snippet     string // Short excerpt of the problematic content
}
```

### Error Output

Findings are formatted with line numbers and suggestions, consistent with compiler error formatting:

```go
func FormatSecurityFindings(findings []SecurityFinding, filePath string) string {
    // "Security scan found 3 issue(s) in workflow markdown:"
    // Uses formatCompilerErrorWithPosition for consistent formatting
}
```

---

## 14. Expression Safety Allowlist

GitHub Actions expressions (`${{ ... }}`) are validated against an allowlist to prevent injection of arbitrary expressions that could exfiltrate secrets or modify behavior.

### Allowed Expression Patterns

```go
// File: pkg/workflow/expression_safety_validation.go

var (
    // needs.step_id.outputs.* and steps.step_id.outputs.*
    needsStepsRegex = regexp.MustCompile(`^(needs|steps)\.[a-zA-Z0-9_-]+(\.[a-zA-Z0-9_-]+)*$`)

    // github.event.inputs.input_name (workflow dispatch)
    inputsRegex = regexp.MustCompile(`^github\.event\.inputs\.[a-zA-Z0-9_-]+$`)

    // inputs.input_name (reusable workflow calls)
    workflowCallInputsRegex = regexp.MustCompile(`^inputs\.[a-zA-Z0-9_-]+$`)

    // github.aw.inputs.* (gh-aw specific)
    awInputsRegex = regexp.MustCompile(`^github\.aw\.inputs\.[a-zA-Z0-9_-]+$`)

    // env.VAR_NAME
    envRegex = regexp.MustCompile(`^env\.[a-zA-Z0-9_-]+$`)
)
```

### Validation Flow

```go
func validateExpressionSafety(markdownContent string) error {
    matches := expressionRegex.FindAllStringSubmatch(markdownContent, -1)

    for _, match := range matches {
        expression := strings.TrimSpace(match[1])

        // Reject multi-line expressions
        if strings.Contains(match[1], "\n") {
            unauthorizedExpressions = append(...)
            continue
        }

        // Parse expression tree for complex expressions (a || b, comparisons)
        parsed, parseErr := ParseExpression(expression)
        if parseErr == nil {
            // Validate each leaf expression in the tree
            VisitExpressionTree(parsed, func(expr *ExpressionNode) error {
                return validateSingleExpression(expr.Expression, options)
            })
        } else {
            // Fallback: validate whole expression as literal
            validateSingleExpression(expression, options)
        }
    }
}
```

### Fuzzy Match Suggestions

When an unauthorized expression is found, the system suggests up to 7 similar allowed expressions:

```go
const maxFuzzyMatchSuggestions = 7
// "Did you mean 'github.event.issue.number' instead of 'github.event.issue.num'?"
```

### Expression Tree Support

Complex expressions like `github.ref == 'main' || github.ref == 'develop'` are parsed into a tree and each leaf is validated individually. The `||` fallback pattern (`value || 'default'`) is also supported.

---

## 15. Dangerous Permissions Enforcement

The agent job is enforced as **read-only**. Any attempt to add write permissions to the workflow-level permissions block is rejected at compile time.

### The Rule

> "The agent job must not have write permissions. All writes must go through safe-outputs, which uses a scoped GitHub App token."

### Implementation

```go
// File: pkg/workflow/dangerous_permissions_validation.go

func validateDangerousPermissions(workflowData *WorkflowData) error {
    permissions := NewPermissionsParser(workflowData.Permissions).ToPermissions()

    writePermissions := findWritePermissions(permissions)
    if len(writePermissions) > 0 {
        return formatDangerousPermissionsError(writePermissions)
    }
    return nil
}

func findWritePermissions(permissions *Permissions) []PermissionScope {
    var writePerms []PermissionScope
    for _, scope := range GetAllPermissionScopes() {
        // Skip id-token (safe, used for OIDC) and metadata (built-in read-only)
        if scope == PermissionIdToken || scope == PermissionMetadata {
            continue
        }
        level, exists := permissions.Get(scope)
        if exists && level == PermissionWrite {
            writePerms = append(writePerms, scope)
        }
    }
    return writePerms
}
```

### Error Message

The error is detailed and actionable:

```
The agent job must not have write permissions.
The agent job should stay read-only. All writes must go through safe-outputs,
which uses a scoped GitHub App token. See: docs/safe-outputs.md

Found write permissions on agent job:
  - contents: write
  - issues: write

To fix this issue, remove write permissions and use safe-outputs instead.
If read access is still needed, keep the read permission:
permissions:
  contents: read
  issues: read
```

### Scope

This validation applies to:
- Top-level workflow permissions

This validation does **NOT** apply to:
- Custom jobs (explicitly authored by the user)
- Safe outputs jobs (permissions computed automatically)

---

## 16. Strict Mode

Strict mode is an opt-in production hardening layer that enforces additional security constraints beyond the defaults.

### What Strict Mode Enforces

```go
// File: pkg/workflow/strict_mode_validation.go

func (c *Compiler) validateStrictMode(frontmatter map[string]any, network *NetworkPermissions) error {
    collector := NewErrorCollector(c.failFast)

    // 1. Refuse write permissions on sensitive scopes
    collector.Add(c.validateStrictPermissions(frontmatter))

    // 2. Require explicit network configuration (no implicit defaults)
    //    Refuse "*" wildcard (unrestricted network)
    collector.Add(c.validateStrictNetwork(networkPermissions))

    // 3. Require top-level network config for container-based MCP servers
    collector.Add(c.validateStrictMCPNetwork(frontmatter, networkPermissions))

    // 4. Validate tools configuration (e.g., reject serena local mode)
    collector.Add(c.validateStrictTools(frontmatter))

    // 5. Refuse deprecated fields
    collector.Add(c.validateStrictDeprecatedFields(frontmatter))

    return collector.FormattedError("strict mode")
}
```

### Strict Mode Validations

| Validation | What It Checks |
|-----------|----------------|
| `validateStrictPermissions` | No write permissions on sensitive scopes |
| `validateStrictNetwork` | Network config must be explicit; `"*"` wildcard refused |
| `validateStrictMCPNetwork` | Container MCP servers must have network config at top level |
| `validateStrictTools` | Tool configs are safe (e.g., no local-mode tools in production) |
| `validateStrictDeprecatedFields` | Deprecated frontmatter fields are rejected |

### Integration with Zizmor

Strict mode also affects the [zizmor](https://github.com/woodruffw/zizmor) security scanner. When zizmor is enabled with `--zizmor`, strict mode promotes security findings from **warnings to errors**:

```go
// In pkg/cli/zizmor.go:
// When strict mode + zizmor: any findings = compilation error
// Without strict mode: findings = warnings only
```

### Environment Secrets Validation

Env secrets validation (`validateEnvSecrets`) is called **separately** from strict mode — it emits **warnings** in normal mode and **errors** in strict mode. This provides a gradual enforcement path.

---

## 17. Threat Detection

Threat detection is an AI-based post-processing step that analyzes agent outputs for malicious or suspicious content **before** they are executed. It runs the same agentic engine but in a **fully sandboxed, network-blocked** environment.

### Architecture

```
Agent Job:
  1. Agent runs and produces outputs (JSONL + patches)
  2. collect_output step gathers outputs
  3. Threat detection guard checks if analysis is needed
  4. Clear MCP configs (detection runs without MCP servers)
  5. Prepare files (copy outputs to detection directory)
  6. Setup threat detection prompt
  7. Run detection engine (AWF, no network, no MCP)
  8. Custom threat detection steps (optional)
  9. Parse results
  10. Upload detection log artifact
  11. Set conclusion (success/failure/skipped)
```

### Configuration

```yaml
---
safe-outputs:
  threat-detection: true       # Enable with defaults
  # OR
  threat-detection:
    enabled: true
    prompt: "Extra instructions for the threat detection agent"
    engine: "claude"           # Override engine (or false to disable AI)
    runs-on: "ubuntu-latest"   # Runner override
    steps:                     # Custom analysis steps
      - name: Custom scan
        run: ./my-scanner.sh
---
```

### Key Security Properties

1. **Network fully blocked**: Detection engine runs with `Allowed: []string{}` — zero network egress
2. **No MCP servers**: MCP config files are cleared before detection runs
3. **Same sandbox**: Uses AWF firewall like the main agent
4. **Separate engine instance**: Can use a different model for cost optimization

```go
// File: pkg/workflow/threat_detection.go

threatDetectionData := &WorkflowData{
    Tools: map[string]any{
        "bash": []any{"cat", "head", "tail", "wc", "grep", "ls", "jq"},
    },
    SafeOutputs:    nil,   // No safe outputs
    IsDetectionRun: true,
    NetworkPermissions: &NetworkPermissions{
        Allowed: []string{}, // deny-all: no network access
    },
    SandboxConfig: &SandboxConfig{
        Agent: &AgentSandboxConfig{
            Type: SandboxTypeAWF,
        },
    },
}
```

### Detection Guard

Detection only runs when there are actual outputs to analyze:

```go
func (c *Compiler) buildDetectionGuardStep() []string {
    // If output_types is non-empty OR has_patch is true → run detection
    // Otherwise → skip (no outputs to analyze)
}
```

### Detection Conclusion

The final step sets outputs that downstream jobs use to decide whether to proceed:

```
conclusion: success  → Agent outputs are safe
conclusion: failure  → Threat detected
conclusion: skipped  → No outputs to analyze
```

---

## 18. Supply Chain Security (Action Pinning)

All GitHub Actions used in compiled workflows are **pinned to specific commit SHAs** to prevent supply chain attacks.

### How It Works

```go
// File: pkg/workflow/action_pins.go

//go:embed data/action_pins.json
var actionPinsJSON []byte

type ActionPin struct {
    Repo    string `json:"repo"`    // "actions/checkout"
    Version string `json:"version"` // "v5"
    SHA     string `json:"sha"`     // Full 40-char commit SHA
}
```

### Pin Format

Instead of mutable tags:
```yaml
# UNSAFE: tag can be moved to point to different code
- uses: actions/checkout@v4
```

The compiler generates:
```yaml
# SAFE: immutable commit SHA with version comment
- uses: actions/checkout@abc123def456... # v4.1.0
```

### Pin Data

The pin data is:
- Embedded at compile time via `//go:embed data/action_pins.json`
- Parsed once and cached (thread-safe via `sync.Once`)
- Sorted deterministically for reproducible output
- Validated for key/version mismatches during loading

```go
func getActionPins() []ActionPin {
    actionPinsOnce.Do(func() {
        var data ActionPinsData
        json.Unmarshal(actionPinsJSON, &data)

        // Detect and warn about key/version mismatches
        for key, pin := range data.Entries {
            if keyVersion != pin.Version {
                actionPinsLog.Printf("WARNING: Key/version mismatch: key=%s version=%s", key, pin.Version)
            }
        }
    })
    return cachedActionPins
}
```

### SHA Verification

The `action_sha_checker.go` module verifies SHAs against the GitHub API to detect if pins are stale or tampered with.

---

## 19. Audit & Compliance

The audit system provides comprehensive logging and reporting for all agentic workflow runs.

### Audit CLI

```
gh aw audit              # View audit report for recent runs
gh aw audit --analysis   # Include AI-powered analysis
```

### Audit Components

| File | Purpose |
|------|---------|
| `pkg/cli/audit.go` | Audit command implementation |
| `pkg/cli/audit_report.go` | Report data collection |
| `pkg/cli/audit_report_analysis.go` | AI-powered analysis of runs |
| `pkg/cli/audit_report_render.go` | Terminal/markdown rendering |
| `pkg/cli/audit_report_helpers_test.go` | Helper tests |

### What's Audited

- All safe output operations (from manifest)
- Threat detection results
- DIFC filtering events
- Redacted URLs/domains
- Code-push failures and fallbacks
- MCP tool usage patterns
- Agent session metadata

---

## 20. Staged Mode (Dry-Run Previews)

Staged mode allows previewing safe output operations without executing them. This is useful for testing workflows and reviewing what the agent would do.

### Enabling Staged Mode

```yaml
---
safe-outputs:
  staged: true              # Global: all handlers in staged mode
  create-issue:
    staged: true             # Per-handler: only this handler is staged
---
```

### How It Works

1. **Compile time**: Staged handlers are excluded from permission computation → `permissions: {}`
2. **Runtime**: The processor detects `GH_AW_SAFE_OUTPUTS_STAGED=true` and generates a preview instead of making API calls

```javascript
// File: actions/setup/js/safe_output_processor.cjs

if (process.env.GH_AW_SAFE_OUTPUTS_STAGED === "true") {
    await generateStagedPreview({
        title: stagedPreviewOptions.title,
        description: stagedPreviewOptions.description,
        items: items,
        renderItem: stagedPreviewOptions.renderItem,
    });
    return { success: false, reason: "Staged mode - preview generated" };
}
```

### Preview Output

Staged previews are written to the GitHub Actions step summary with a distinctive marker:

```
🎭 Staged Preview: Create Issue
This is a staged preview. No changes were made.

- Title: [Bot] Bug found in module X
- Body: (truncated preview)
- Labels: bug, automated
```

### Security Benefit

Staged mode is a zero-trust testing mechanism:
- No write tokens are requested
- No API calls are made
- No side effects occur
- Full audit trail of what *would* have happened

---

## 21. Guard Policies

Guard policies configure how the MCP Gateway enforces access control on tool calls. They implement the DIFC enforcement layer.

### Configuration Format

Guard policies are rendered in both JSON (for HTTP-based gateways) and TOML (for config-file-based gateways):

```go
// File: pkg/workflow/mcp_renderer_guard.go

// JSON format:
func renderGuardPoliciesJSON(yaml *strings.Builder, policies map[string]any, indent string) {
    jsonBytes, _ := json.MarshalIndent(policies, indent, "  ")
    fmt.Fprintf(yaml, "%s\"guard-policies\": %s\n", indent, string(jsonBytes))
}

// TOML format:
func renderGuardPoliciesToml(yaml *strings.Builder, policies map[string]any, serverID string) {
    // [mcp_servers.server_id."guard-policies".write-sink]
    // accept = ["private:github/gh-aw*"]
}
```

### Policy Types

| Policy | Purpose |
|--------|---------|
| `allow-only` | Only allow access to matching resources |
| `write-sink` | Control which resources can be written to |
| `deny` | Block access to matching resources |

### Policy Configuration Example

```json
{
  "guard-policies": {
    "write-sink": {
      "accept": ["private:github/org-name*"],
      "min_integrity": "medium"
    },
    "allow-only": {
      "accept": ["private:github/specific-repo*"],
      "max_secrecy": "internal"
    }
  }
}
```

### Integration with DIFC

Guard policies reference integrity and secrecy levels. When a tool call targets a resource that doesn't meet the policy requirements, the gateway emits a `DIFC_FILTERED` event and blocks the call.

---

## 22. MCP Logs Guardrail

The MCP logs guardrail prevents overwhelming responses when querying workflow logs via MCP tools.

### How It Works

```go
// File: pkg/cli/mcp_logs_guardrail.go

const (
    DefaultMaxMCPLogsOutputTokens = 12000  // ~12K tokens
    CharsPerToken                 = 4       // ~4 chars/token approximation
)

func checkLogsOutputSize(outputStr string, maxTokens int) (string, bool) {
    outputTokens := estimateTokens(outputStr) // len(text) / CharsPerToken

    if outputTokens <= maxTokens {
        return outputStr, false // Within limits
    }

    // Generate guardrail response with schema info
    guardrail := MCPLogsGuardrailResponse{
        Message: fmt.Sprintf(
            "Output size (%d tokens) exceeds limit (%d tokens). " +
            "Narrow your query with filters.",
            outputTokens, maxTokens,
        ),
        OutputTokens:    outputTokens,
        OutputSizeLimit: maxTokens,
        Schema:          getLogsDataSchema(), // Describes available fields
    }

    return json.Marshal(guardrail)
}
```

### Guardrail Response

Instead of returning massive log output that would overwhelm the AI context window, the guardrail returns:

```json
{
  "message": "Output size (45000 tokens) exceeds limit (12000 tokens). Narrow your query.",
  "output_tokens": 45000,
  "output_size_limit": 12000,
  "schema": {
    "description": "Structure of the logs output",
    "type": "object",
    "fields": {
      "workflow_name": { "type": "string", "description": "..." },
      "start_date": { "type": "string", "description": "..." }
    }
  }
}
```

This tells the agent how to narrow its query rather than failing silently or consuming excessive tokens.

---

## 23. Secret Leak Prevention

The project implements a comprehensive, multi-layered approach to preventing environment secrets from leaking into agent containers, output files, logs, or artifacts. The defense spans compile-time detection, runtime redaction, and architectural isolation.

### Layer 1: Compile-Time Secret Detection in `env`

**File**: `pkg/workflow/strict_mode_env_validation.go`

The compiler scans the frontmatter `env` and `engine.env` sections for any secret references. This catches secrets that would be exposed to the agent container.

```go
func (c *Compiler) validateEnvSecrets(frontmatter map[string]any) error {
    // Check top-level env section (no secret overrides allowed)
    if err := c.validateEnvSecretsSection(frontmatter, "env", nil); err != nil {
        return err
    }

    // Check engine.env section (with engine-specific allowlist)
    if engineValue, exists := frontmatter["engine"]; exists {
        if engineObj, ok := engineValue.(map[string]any); ok {
            allowedEnvVarKeys := c.getEngineBaseEnvVarKeys(engineSetting)
            if err := c.validateEnvSecretsSection(engineObj, "engine.env", allowedEnvVarKeys); err != nil {
                return err
            }
        }
    }
    return nil
}
```

**Detection patterns** — catches all these forms:

```yaml
env:
  SIMPLE: "${{ secrets.TOKEN }}"                          # Direct secret
  EMBEDDED: "Bearer ${{ secrets.TOKEN }}"                 # Embedded in string
  SUB_EXPR: "${{ github.workflow && secrets.TOKEN }}"      # Sub-expression
  FALLBACK: "${{ secrets.DB_PASSWORD || env.DEFAULT }}"    # With fallback
  NESTED: "${{ (github.actor || secrets.HIDDEN) }}"        # Nested in parens
```

**Enforcement levels:**
- **Strict mode**: Error — compilation fails
- **Non-strict mode**: Warning — compilation succeeds with a warning

**Engine-specific allowlist:** Engine env vars (like `COPILOT_GITHUB_TOKEN`) are allowed to carry secrets in `engine.env` because they're required by the engine itself. The allowlist is built dynamically from the engine's `GetRequiredSecretNames()` and auth definition:

```go
func (c *Compiler) getEngineBaseEnvVarKeys(engineID string) map[string]bool {
    engine, _ := c.engineRegistry.GetEngine(engineID)
    keys := make(map[string]bool)
    for _, name := range engine.GetRequiredSecretNames(minimalData) {
        keys[name] = true // e.g., "COPILOT_GITHUB_TOKEN"
    }
    // Also include auth-definition secrets for inline engines
    if def := c.engineCatalog.Get(engineID); def != nil && def.Provider.Auth != nil {
        for _, name := range def.Provider.Auth.RequiredSecretNames() {
            keys[name] = true
        }
    }
    return keys
}
```

### Layer 2: Secret Extraction Library

**File**: `pkg/workflow/secret_extraction.go`

A reusable library for extracting and cataloging all secret references from workflow content:

```go
// Extract a single secret name
ExtractSecretName("${{ secrets.DD_API_KEY }}") // → "DD_API_KEY"

// Extract all secrets from a value (handles sub-expressions)
ExtractSecretsFromValue("${{ github.workflow && secrets.TOKEN }}")
// → {"TOKEN": "${{ github.workflow && secrets.TOKEN }}"}

// Extract from an entire env map
ExtractSecretsFromMap(map[string]string{
    "DD_API_KEY": "${{ secrets.DD_API_KEY }}",
    "DD_SITE":    "${{ secrets.DD_SITE || 'datadoghq.com' }}",
})
// → {"DD_API_KEY": "${{ secrets.DD_API_KEY }}", "DD_SITE": "${{ secrets.DD_SITE || 'datadoghq.com' }}"}

// Replace secret expressions with safe env var references
ReplaceSecretsWithEnvVars(value) // → converts ${{ secrets.X }} to $X
```

The pattern matches `${{ secrets.SECRET_NAME }}` with optional fallbacks, and handles secrets embedded in larger expressions.

### Layer 3: MCP API Key Immediate Masking

**File**: `pkg/workflow/mcp_setup_generator.go`

API keys generated at runtime for the MCP gateway, safe outputs server, and MCP scripts are masked **immediately** after generation — no timing window where the value is exposed in logs:

```bash
# Generated in compiled workflow YAML:
# Generate a secure random API key (360 bits of entropy, 40+ chars)
# Mask immediately to prevent timing vulnerabilities
API_KEY=$(openssl rand -base64 45 | tr -d '/+=')
echo "::add-mask::${API_KEY}"    # ← Masked BEFORE any other use
```

This pattern is applied in three places:
1. Safe Outputs MCP server API key
2. MCP Scripts API key
3. MCP Gateway API key

**Tested by**: `pkg/workflow/mcp_api_key_masking_test.go` — verifies:
- Immediate masking after generation (no gap)
- No empty variable declarations before assignment
- Consistent pattern across all three API key types

### Layer 4: Runtime Secret Redaction from Output Files

**Files**: `pkg/workflow/redact_secrets.go` (Go) + `actions/setup/js/redact_secrets.cjs` (JS)

A two-part system that scans and redacts secrets from all output files before artifact upload.

**Go side** — scans the compiled YAML for `secrets.([A-Z][A-Z0-9_]*)` patterns and generates a GitHub Actions step that:
1. Passes secret names as `GH_AW_SECRET_NAMES` env var
2. Passes actual secret values as individual env vars (for exact-match redaction)

```go
func (c *Compiler) generateSecretRedactionStep(yaml *strings.Builder, yamlContent string, data *WorkflowData) {
    secretReferences := CollectSecretReferences(yamlContent)

    // Always generate the step (even if no-op) for consistent step ordering
    if len(secretReferences) == 0 {
        // No-op step
        yaml.WriteString("      - name: Redact secrets in logs\n")
        yaml.WriteString("        if: always()\n")
        yaml.WriteString("        run: echo 'No secrets to redact'\n")
    } else {
        // Full redaction step with secret values as env vars
    }
}
```

**JS side** — processes all files under `/tmp/gh-aw` and `$RUNNER_TEMP/gh-aw`:

```javascript
// File: actions/setup/js/redact_secrets.cjs

// File types scanned:
const TARGET_EXTENSIONS = ['.txt', '.json', '.log', '.md', '.mdx', '.yml', '.jsonl'];

// Two-pass redaction:
// 1. Built-in pattern detection (15+ credential types)
// 2. Custom secret exact-match redaction
function processFile(filePath, secretValues) {
    const content = fs.readFileSync(filePath, "utf8");

    // Pass 1: Built-in pattern detection
    const builtInResult = redactBuiltInPatterns(content);

    // Pass 2: Custom secret exact-match
    const customResult = redactSecrets(builtInResult.content, secretValues);

    if (totalRedactions > 0) {
        fs.writeFileSync(filePath, finalContent, "utf8");
    }
}
```

**Built-in credential patterns** (automatically detected even without explicit secret references):

| Provider | Token Type | Pattern |
|----------|-----------|---------|
| GitHub | Personal Access Token (classic) | `ghp_[0-9a-zA-Z]{36}` |
| GitHub | Server-to-Server Token | `ghs_[0-9a-zA-Z]{36}` |
| GitHub | OAuth Access Token | `gho_[0-9a-zA-Z]{36}` |
| GitHub | User Access Token | `ghu_[0-9a-zA-Z]{36}` |
| GitHub | Fine-grained PAT | `github_pat_[0-9a-zA-Z_]{82}` |
| GitHub | Refresh Token | `ghr_[0-9a-zA-Z]{36}` |
| Azure | Storage Account Key | `AccountKey=[a-zA-Z0-9+/]{86}==` |
| Azure | SAS Token | `?sv=...&sig=...` |
| Google | API Key | `AIzaSy[0-9A-Za-z_-]{33}` |
| Google | OAuth Access Token | `ya29.[0-9A-Za-z_-]{1,800}` |
| AWS | Access Key ID | `AKIA[0-9A-Z]{16}` |
| OpenAI | API Key | `sk-[a-zA-Z0-9]{48}` |
| OpenAI | Project API Key | `sk-proj-[a-zA-Z0-9]{48,64}` |
| Anthropic | API Key | `sk-ant-api03-[a-zA-Z0-9_-]{95}` |

**Custom secret redaction** uses exact string matching (not regex) to avoid interpreting special characters. Secrets shorter than 6 characters are skipped to prevent false positives. All redactions use the fixed-length string `***REDACTED***`.

```javascript
function redactSecrets(content, secretValues) {
    // Sort by length (longest first) to handle overlapping secrets
    const sortedSecrets = secretValues.slice().sort((a, b) => b.length - a.length);
    for (const secretValue of sortedSecrets) {
        if (!secretValue || secretValue.length < 6) continue; // Skip short values
        // Exact string matching via split/join (safe, no regex interpretation)
        const parts = redacted.split(secretValue);
        redacted = parts.join("***REDACTED***");
    }
}
```

### Layer 5: Custom Secret Masking Steps

**File**: `pkg/workflow/secret_masking.go`

Workflow authors can define custom masking steps in frontmatter for secrets that don't follow standard patterns:

```yaml
---
secret-masking:
  steps:
    - name: Mask custom secrets
      run: |
        echo "::add-mask::$(cat /tmp/my-custom-secret)"
---
```

Custom masking steps are:
- Extracted from frontmatter via `extractSecretMaskingConfig()`
- Merged from imports via `MergeSecretMasking()`
- Injected into the compiled workflow before the agent runs

### Layer 6: Jobs Secrets Expression Validation

**File**: `pkg/workflow/secrets_validation.go`

When workflows pass secrets to reusable workflows via `jobs.*.secrets`, the expressions are validated against a strict pattern:

```go
// Only allows: ${{ secrets.NAME }} or ${{ secrets.A || secrets.B }}
var pattern = regexp.MustCompile(
    `^\$\{\{\s*secrets\.[A-Za-z_][A-Za-z0-9_]*` +
    `(\s*\|\|\s*secrets\.[A-Za-z_][A-Za-z0-9_]*)*\s*\}\}$`)
```

This prevents accidentally passing plaintext values or env var references where secrets are expected. Importantly, validation error messages don't log secret names (CodeQL protection).

### Layer 7: Architectural Isolation

The fundamental architectural defense: the agent job **never receives write tokens**. Secrets only flow to the safe-outputs job, which has scoped permissions computed at compile time (see [Section 5](#5-least-privilege-permission-computation)).

```
Agent Job:
  - Read-only permissions
  - No access to write tokens
  - Sandboxed with network firewall
  - Output goes to JSONL file

Safe Outputs Job:
  - Scoped write token (minimal permissions)
  - Processes validated/sanitized JSONL
  - Secrets flow HERE, not to agent
```

### Defense-in-Depth Summary

```
┌──────────────────────────────────────────────────────────────┐
│ Layer 1: Compile-Time Detection                               │
│   ├── Detect secrets in env section (strict=error, else warn) │
│   ├── Engine-specific allowlist for required secrets           │
│   └── Jobs secrets expression validation                      │
├──────────────────────────────────────────────────────────────┤
│ Layer 2: Immediate Runtime Masking                            │
│   ├── MCP API keys masked instantly (::add-mask::)            │
│   └── Custom masking steps from frontmatter                   │
├──────────────────────────────────────────────────────────────┤
│ Layer 3: Output File Redaction (before artifact upload)       │
│   ├── Built-in pattern detection (15+ credential formats)     │
│   ├── Custom secret exact-match redaction                     │
│   └── Scans .txt, .json, .log, .md, .yml, .jsonl files       │
├──────────────────────────────────────────────────────────────┤
│ Layer 4: Architectural Isolation                              │
│   ├── Agent job is read-only (no write tokens)                │
│   ├── Secrets only flow to safe-outputs job                   │
│   └── Network sandboxing prevents exfiltration                │
└──────────────────────────────────────────────────────────────┘
```

### Known Limitations: Encoding-Based Evasion

A sophisticated attacker (or a manipulated agent) could attempt to encode secrets (base64, hex, etc.) before committing or exfiltrating them. The project has multiple mitigations but no single deterministic defense covers all encoding scenarios.

#### What IS protected against

**1. Bash encoding tools are not available.** The agent's bash tool is restricted to an explicit allowlist that does **not** include `base64`, `xxd`, `hexdump`, `openssl`, or any encoding utilities:

```go
// File: pkg/constants/constants.go
var DefaultBashTools = []string{
    "echo", "ls", "pwd", "cat", "head", "tail",
    "grep", "wc", "sort", "uniq", "date", "yq",
}
```

This is the primary defense — the agent cannot trivially run `echo $SECRET | base64`.

**2. Threat detection AI explicitly checks for encoded payloads.** The threat detection prompt instructs the reviewer to look for:

> "Base64, hex, or other encoded strings that appear to hide secrets, commands, or malicious payloads without legitimate purpose"

This provides a probabilistic catch for encoded content in agent outputs and patches.

**3. Markdown security scanner detects encoding patterns** in imported workflows:
- Large base64 payloads: `[A-Za-z0-9+/]{200,}={0,2}`
- Hex sequences: repeated `\x[0-9a-fA-F]{2}` patterns (20+ occurrences)
- Decode-and-execute: `base64 -d | bash`, `atob.*eval`

**4. Network sandboxing prevents exfiltration.** Even if the agent encodes a secret, the firewall blocks outbound connections to non-allowed domains. SSL Bump (optional) enables HTTPS content inspection for URL path filtering.

**5. Protected files and allowed files policies** on `push_to_pull_request_branch` restrict which files can be modified in patches.

#### What is NOT fully protected against

**1. Language-runtime encoding.** If the agent has access to a programming language runtime (Python, Node.js, etc.), it could use built-in encoding functions (`import base64; base64.b64encode(...)`) that bypass the bash tool restriction. The bash allowlist doesn't restrict what happens inside language interpreters.

**2. Pattern-based redaction bypass.** The runtime redaction system (Layer 3) scans for **known credential patterns** and **exact string matches**. A base64-encoded secret no longer matches either — `ghp_abc123...` encoded as `Z2hwX2FiYzEyMy4uLg==` would not be caught by pattern matching.

**3. AI threat detection is probabilistic.** The threat detection layer uses an AI model to review outputs, which is effective but not deterministic. A well-crafted encoding scheme (e.g., splitting the encoded value across multiple files, or using a custom alphabet) could evade detection.

**4. No pre-commit secret scanning hooks.** The project does not use tools like git-secrets, truffleHog, or gitleaks as pre-commit/pre-push hooks that would scan committed content for high-entropy strings or known secret patterns.

#### Recommendations for replication

If implementing this architecture in a project where encoding evasion is a concern:

1. **Add a deterministic secret scanner** (truffleHog, gitleaks, or detect-secrets) as a post-processing step on all patches before they are committed. These tools detect high-entropy strings regardless of format.
2. **Restrict language runtime access** where possible — if the agent doesn't need Python, don't provide it.
3. **Monitor for encoding function calls** in agent logs and tool usage (e.g., flag calls to `btoa`, `base64`, `Buffer.from` in the audit system).
4. **Implement content-aware diffing** — compare the information-theoretic entropy of patch content against baseline; high-entropy blobs in unexpected locations may indicate encoded secrets.

---

## Summary: Replication Checklist

To replicate this safety architecture in another project, implement these layers in order of priority:

### Must-Have (Core Safety)

1. **Privilege separation**: Read-only agent, scoped write tokens for output execution
2. **Typed output schema**: Strict JSON schema with `additionalProperties: false`
3. **Least-privilege permissions**: Compute minimal token scopes from enabled handlers
4. **Content sanitization**: URL filtering, mention neutralization, unicode hardening
5. **Input validation**: Max counts, allowed values, required fields, target resolution

### Should-Have (Defense in Depth)

6. **Network sandboxing**: Firewall/proxy controlling agent network egress
7. **Template injection prevention**: Detect `${{ }}` in shell commands
8. **Expression allowlist**: Only permit known-safe expressions
9. **Dangerous permissions enforcement**: Block write permissions on agent job
10. **Supply chain security**: Pin action SHAs, not mutable tags

### Should-Have (continued)

11. **Secret leak prevention**: Compile-time detection, runtime redaction, built-in credential pattern matching, immediate API key masking

### Nice-to-Have (Production Hardening)

12. **Staged mode**: Dry-run preview without side effects
13. **Threat detection**: AI-based review of agent outputs before execution
14. **DIFC**: Integrity and secrecy labels with gateway enforcement
15. **Strict mode**: Production hardening with zero-tolerance for violations
16. **Markdown security scanning**: Detect malicious content in imported workflows
17. **Audit & compliance**: Comprehensive logging and reporting
18. **MCP logs guardrail**: Prevent context window overflow from large outputs
19. **Guard policies**: Fine-grained MCP gateway access control
