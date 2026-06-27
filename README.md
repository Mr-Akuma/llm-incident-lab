# From Chat Box to Cloud Admin

### A runnable LLM security incident - tool-choice manipulation -> approval-gate bypass -> privilege escalation

A small, hand-traceable lab built against the
[LLM Threat Coverage Atlas](https://mr-akuma.github.io/llm-threat-model-full-267-bubble-atlas.html).
A single chat message turns a **low-privilege support agent** into a
**cloud administrator** - rotating a production master key and deleting another
tenant's database - and the same message fools the "ask another AI to approve it"
gate. The bug is not in the model. It's in the **harness** that decides which tool
calls run.

> Full write-up: `docs/from-chat-box-to-cloud-admin.html` (or `docs/blog.md`).

```bash
python run_incident.py                 # the main attack, vulnerable then patched
python run_incident.py --scenario all  # benign, attack, recon, exfil
python run_incident.py --real          # a faithful Claude tool-use loop (needs ANTHROPIC_API_KEY)
python eval.py                         # Attack Success Rate table
python -m pytest -q                    # regression suite (also: python -m unittest test_lab)
```

Pure stdlib for the scripted path - nothing to install. `--real` needs `pip install anthropic`.

## The chain (three Atlas domains)

| Step | Atlas | Mistake in the harness | Fix |
|------|-------|------------------------|-----|
| **D** Tool Use | tool-choice manipulation | runs whatever tool the steered model picks | tier tools; gate the destructive tier |
| **E** Approval Gates | approval-gate bypass | "approved?" is decided by an **LLM judge that reads the same attacker text** | approval out-of-band, never from a model |
| **F** Identity & Authz | broken authorization | no caller role / tenant check | check role + resource owner before executing |

Plus **H** (output handling) in the `exfil` scenario: the agent embeds a secret in a
markdown image URL and rendering it leaks the data - no "send" tool required.

## Scenarios

| Scenario | What it shows |
|----------|---------------|
| `benign` | the agent as a normal, helpful tool (the contrast) |
| `attack` | rotate + delete via the LLM-judge approval bypass, cross-tenant |
| `recon`  | multi-turn: safe discovery, then the destructive step |
| `exfil`  | read a secret, leak it through a rendered markdown image |

## The fix (one method, `Harness._gate`)

```python
# VULNERABLE: ask an LLM judge that reads the attacker-controlled conversation
if self.backend.judge(self.transcript, call):
    return True, "approved by LLM judge (reads attacker text)"

# PATCHED: model/judge are never trusted for an irreversible action
call.args.pop("approval_note", None)                       # ignore model approval
ok, why = _allowed(self.caller, call.name, call.args, ...)  # F: role + tenant
if not ok: return False, why
if self.approve(call): return True, "human approved (out-of-band)"   # E
return False, "human denied / no approval"
```

**Reversibility decides the gate.** Read-only tools run freely; irreversible tools need
authorization the model can't influence **plus** out-of-band approval. Beyond the gate:
dual-LLM / quarantined-LLM, CaMeL, and spotlighting (see the write-up).

## Detection

`detect()` replays the audit log; `detections/agent_privilege_escalation.yml` is a Sigma
rule for the one correlation that's never benign:

> privileged tool call (or egress) × non-admin caller × cross-tenant target.

## Files

| File | Role |
|------|------|
| `cloud.py` | in-memory control plane (resources, secrets, audit + egress log) |
| `tools.py` | tiered tool surface (safe / sensitive / privileged / output) |
| `backends.py` | scripted backend + faithful Claude tool-use loop + the LLM judge |
| `harness.py` | the security boundary; `secure` switch toggles vuln/patched |
| `run_incident.py` | runs the scenarios + detection |
| `eval.py` | Attack Success Rate across scenarios/models |
| `test_lab.py` | pytest/unittest regression suite |
| `detections/agent_privilege_escalation.yml` | Sigma detection rule |
| `docs/` | the write-up (HTML + Markdown) and all diagrams |

Educational / defensive use. Everything runs against an in-memory fake cloud - no real
systems are touched. `--real` exercises a true Claude tool-use loop to show the harness,
not the model, is the vulnerable component.
