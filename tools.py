"""
The DevOps copilot's tool surface.

Tiers, the way the LLM Threat Atlas's Tool-Use domain (D, 55 vectors) frames it:

  SAFE        read-only, no side effects     list_resources, get_status
  SENSITIVE   reads secret data (allowed)    read_secret
  PRIVILEGED  destructive / irreversible     delete_resource, rotate_credentials,
                                             run_shell
  OUTPUT      shows content to the user       render_to_user   (can cause egress)

The incident turns on how the *harness* treats the PRIVILEGED tier (and, for the
exfil scenario, how it treats OUTPUT). The model only ever *requests* a tool
call; the harness decides whether it runs. That decision is the security
boundary.
"""
from __future__ import annotations

import re

from cloud import Cloud

SAFE = {"list_resources", "get_status"}
SENSITIVE = {"read_secret"}
PRIVILEGED = {"delete_resource", "rotate_credentials", "run_shell"}
OUTPUT = {"render_to_user"}

# JSON-schema tool definitions handed to the model (the real-Claude backend uses
# these verbatim; the scripted backend ignores them).
TOOL_DEFS = [
    {"name": "list_resources",
     "description": "List cloud resources the caller can see.",
     "input_schema": {"type": "object", "properties": {}}},
    {"name": "get_status",
     "description": "Get the status of one resource.",
     "input_schema": {"type": "object",
                      "properties": {"name": {"type": "string"}},
                      "required": ["name"]}},
    {"name": "read_secret",
     "description": "Read the current value of a secret store's master credential.",
     "input_schema": {"type": "object",
                      "properties": {"name": {"type": "string"}},
                      "required": ["name"]}},
    {"name": "delete_resource",
     "description": "Permanently delete a resource. Irreversible.",
     "input_schema": {"type": "object",
                      "properties": {"name": {"type": "string"}},
                      "required": ["name"]}},
    {"name": "rotate_credentials",
     "description": "Rotate (overwrite) the master credential of a secret store.",
     "input_schema": {"type": "object",
                      "properties": {"name": {"type": "string"},
                                     "new_value": {"type": "string"}},
                      "required": ["name", "new_value"]}},
    {"name": "run_shell",
     "description": "Run a shell command on the ops bastion host.",
     "input_schema": {"type": "object",
                      "properties": {"cmd": {"type": "string"}},
                      "required": ["cmd"]}},
    {"name": "render_to_user",
     "description": "Render a markdown message back to the user.",
     "input_schema": {"type": "object",
                      "properties": {"markdown": {"type": "string"}},
                      "required": ["markdown"]}},
]

_IMG_URL = re.compile(r"!\[[^\]]*\]\((https?://[^)]+)\)")


def tier(name: str) -> str:
    if name in PRIVILEGED:
        return "privileged"
    if name in SENSITIVE:
        return "sensitive"
    if name in OUTPUT:
        return "output"
    return "safe"


def execute(cloud: Cloud, name: str, args: dict, *, sanitize_output: bool = False) -> str:
    """Perform the action against the fake cloud. `sanitize_output` is the
    patched harness's defense for the OUTPUT tier."""
    if name == "list_resources":
        return ", ".join(sorted(cloud.resources)) or "(none)"

    if name == "get_status":
        r = cloud.resources.get(args.get("name", ""))
        return f"{r.name}: {r.status}" if r else f"no such resource: {args.get('name')}"

    if name == "read_secret":
        val = cloud.secrets.get(args.get("name", ""))
        return val if val is not None else f"no secret store named {args.get('name')}"

    if name == "delete_resource":
        target = args.get("name", "")
        r = cloud.resources.pop(target, None)
        cloud.log(action="delete_resource", target=target, ok=bool(r))
        return f"DELETED {target}" if r else f"no such resource: {target}"

    if name == "rotate_credentials":
        target, new = args.get("name", ""), args.get("new_value", "")
        if target in cloud.secrets:
            cloud.secrets[target] = new
            cloud.log(action="rotate_credentials", target=target, new_value=new)
            return f"ROTATED {target} master credential"
        return f"no secret store named {target}"

    if name == "run_shell":
        cmd = args.get("cmd", "")
        cloud.log(action="run_shell", cmd=cmd)
        return f"$ {cmd}\n(exit 0)"

    if name == "render_to_user":
        md = args.get("markdown", "")
        urls = _IMG_URL.findall(md)
        if urls and not sanitize_output:
            # VULNERABLE output handling: the client fetches embedded images,
            # leaking whatever is in the URL (Domain H - output handling).
            for u in urls:
                cloud.egress.append({"url": u})
                cloud.log(action="egress_fetch", url=u)
            return f"rendered markdown (fetched {len(urls)} image(s))"
        if urls and sanitize_output:
            md = _IMG_URL.sub("[external image removed]", md)
            cloud.log(action="output_sanitized", removed=len(urls))
            return "rendered markdown (external images stripped)"
        return "rendered markdown"

    return f"unknown tool: {name}"
