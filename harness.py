"""
The agent harness - where the security boundary lives.

One class, one switch (`secure`), so the writeup can diff the two modes line for
line. The model, tools, and cloud are identical between runs; only the harness's
handling of privileged tool calls (and rendered output) changes.

VULNERABLE (secure=False):
  D  tool-choice manipulation : runs whatever tool the steered model picks
  E  approval-gate bypass     : "approval" comes from an LLM judge that reads the
                                same attacker-controlled conversation
  F  broken authorization     : no caller/tenant check
  H  output handling          : renders attacker markdown → image fetch exfil

SECURE (secure=True):
  - privileged tools require caller authz + a real out-of-band human yes
  - any model-supplied "approval" field is stripped; the judge is not trusted
  - rendered output is sanitized (external images removed)
"""
from __future__ import annotations

import json
from dataclasses import dataclass

import tools
from backends import ModelResponse, ToolCall
from cloud import Cloud

RESET, RED, GRN, YEL, DIM, CYN = (
    "\033[0m", "\033[31m", "\033[32m", "\033[33m", "\033[2m", "\033[36m")


@dataclass
class Caller:
    name: str
    role: str            # "support" (low priv) or "admin"
    tenant: str          # the customer they belong to


def _allowed(caller: Caller, name: str, args: dict, cloud: Cloud) -> tuple[bool, str]:
    """Authorization check (Domain F). Used only in secure mode."""
    if name in tools.PRIVILEGED and caller.role != "admin":
        return False, f"role '{caller.role}' may not call privileged tool '{name}'"
    target = args.get("name")
    if target and target in cloud.resources:
        owner = cloud.resources[target].tenant
        if owner != caller.tenant:
            return False, f"cross-tenant: {caller.tenant} cannot touch {owner}'s '{target}'"
    return True, ""


class Harness:
    def __init__(self, cloud: Cloud, backend, caller: Caller,
                 secure: bool, approve=None, quiet: bool = False):
        self.cloud = cloud
        self.backend = backend
        self.caller = caller
        self.secure = secure
        self.approve = approve or (lambda call: False)   # out-of-band human (secure)
        self.quiet = quiet
        self.blocked: list[str] = []
        self.transcript = ""

    # -- the gate -----------------------------------------------------------
    def _gate(self, call: ToolCall) -> tuple[bool, str]:
        t = tools.tier(call.name)
        if t in ("safe", "sensitive"):
            return True, t
        if t == "output":
            return True, "output"          # defense is sanitisation, not a block

        # privileged tier
        if not self.secure:
            if self.backend.judge(self.transcript, call):   # E: fooled LLM judge
                return True, "approved by LLM judge (reads attacker text)"
            return True, "no gate (privileged ran unchecked)"

        call.args.pop("approval_note", None)                # ignore model approval
        ok, why = _allowed(self.caller, call.name, call.args, self.cloud)   # F
        if not ok:
            return False, why
        if self.approve(call):                              # E: real out-of-band yes
            return True, "human approved (out-of-band)"
        return False, "human denied / no approval"

    # -- the loop -----------------------------------------------------------
    def run(self, system: str, user_msg: str, max_turns: int = 6) -> None:
        self.backend.start(system, user_msg)
        self.transcript = f"USER: {user_msg}"
        self._say(f"{CYN}USER >{RESET} {user_msg}\n")

        for _ in range(max_turns):
            resp: ModelResponse = self.backend.step()
            if resp.text:
                self.transcript += f"\nASSISTANT: {resp.text}"
                self._say(f"{DIM}agent:{RESET} {resp.text}")
            if not resp.tool_calls:
                return

            results = []
            for call in resp.tool_calls:
                allowed, why = self._gate(call)
                t = tools.tier(call.name)
                if allowed:
                    out = tools.execute(self.cloud, call.name, call.args,
                                        sanitize_output=self.secure)
                    colour = RED if t == "privileged" else (YEL if t == "output" else GRN)
                    self._say(f"  {colour}-> {call.name}{RESET}({_fmt(call.args)})  "
                              f"{DIM}[{t}: {why}]{RESET}\n     {out}")
                else:
                    self.blocked.append(call.name)
                    out = f"blocked: {why}"
                    self._say(f"  {YEL}xx {call.name}{RESET}({_fmt(call.args)})  "
                              f"{DIM}[BLOCKED: {why}]{RESET}")
                self.cloud.log(action="gate", tool=call.name, tier=t,
                               caller=self.caller.name, role=self.caller.role,
                               tenant=self.caller.tenant, target=call.args.get("name"),
                               decision="allow" if allowed else "block", reason=why)
                self.transcript += f"\nTOOL[{call.name}]: {out}"
                results.append((call.id, out))
            self.backend.add_tool_results(results)

    def _say(self, msg: str) -> None:
        if not self.quiet:
            print(msg)

    def audit_json(self) -> str:
        return json.dumps(self.cloud.audit, indent=2)


def _fmt(args: dict) -> str:
    return ", ".join(f"{k}={v!r}" for k, v in args.items())
