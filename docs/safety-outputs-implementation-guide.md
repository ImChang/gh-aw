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
