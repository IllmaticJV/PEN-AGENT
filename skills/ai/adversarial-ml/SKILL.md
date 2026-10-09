---
name: adversarial-ml
description: >
  Craft adversarial inputs that fool non-LLM ML classifiers — image
  recognition, speech-to-text, NLP sentiment, tabular fraud/IDS. Covers
  FGSM / PGD / Carlini-Wagner for white-box, query-based (ZOO,
  SquareAttack) and transfer attacks for black-box, plus physical-world
  patch attacks. Use when the target is a deployed classifier (not an
  LLM) and the engagement includes evasion testing. For LLM-side input
  manipulation use prompt-injection; this skill is for the ML models
  LLMs don't cover.
keywords:
  - adversarial examples
  - adversarial ML
  - evasion attack
  - FGSM
  - PGD
  - Carlini-Wagner
  - adversarial patch
  - transfer attack
  - adversarial image
  - adversarial audio
  - IDS evasion
  - fraud detection bypass
  - OWASP ML01
  - OSAI AI-300
tools:
  - python3
  - torch
  - foolbox
  - torchattacks
opsec: medium
---

# Adversarial ML (Classifier Evasion)

You are helping a penetration tester test an ML classifier's
robustness to adversarial inputs — crafted perturbations that look
benign to a human but push the model past its decision boundary.
Common targets: image classifiers (CV), face recognition, speech-to-
text, NLP sentiment / classification, tabular fraud detectors, IDS
anomaly scorers. All testing is under explicit written
authorization against the pre-approved target in scope.

## Engagement Logging

Check for `./engagement/` directory. If absent, proceed without logging.

When an engagement directory exists:
- Print `[adversarial-ml] Activated → <target>` on activation.
- **Evidence** → save adversarial examples, their clean counterparts,
  and the attack configuration to
  `engagement/evidence/adversarial-<target>/` — one directory per
  attack run with `clean.png` / `adv.png` / `attack.json` / per-
  query log.

## Scope Boundary

This skill covers evasion of a deployed classifier via adversarial
inputs. Training-time attacks (data poisoning, backdoors) belong in
`ml-supply-chain`. Model-weight recovery belongs in
`model-extraction`. On a confirmed evasion (adversarial example
flips the classification across a configured confidence threshold),
**STOP** and return to the orchestrator with the proof.

**Stay inside the authorization boundary.** Adversarial inputs can
trigger alerts on hardened defenders — the operator's engagement
scope sets how many evasion attempts you may run and against which
sample set. Do not attack production classifiers whose decisions
affect real users (fraud flagging, medical triage) outside the
agreed window.

## State Management

Call `get_state_summary()`. Check prior ai-recon for:
- The classifier's modality (image / audio / NLP / tabular)
- Access mode (white-box with weights, grey-box with logits,
  black-box with hard labels only)
- Any sample inputs the operator provided

Report back:
- Attack class run (white-box optimisation / query-based /
  transfer / physical-patch)
- Query count and success rate on the sample set
- Perturbation magnitude (`L_inf`, `L_2`, or patch size)
- Finding id

## Prerequisites

- Target classifier reachable (API endpoint, offline model file, or
  physical sensor-feed setup).
- Access mode confirmed with the operator:
  - **White-box**: model weights available on the attackbox
  - **Grey-box**: API returns logits / confidences
  - **Black-box**: API returns only predicted label
- `python3` with `torch` + `torchattacks` or `foolbox`. For speech
  attacks `torchaudio`; for NLP `textattack`.
- Sample inputs the engagement authorized you to perturb (do NOT
  perturb inputs the operator did not supply — using live
  customer data in a test is out of scope).

## Attack Variants

### Variant A — White-box: PGD / Carlini-Wagner

The strongest attacks when you have the model weights. PGD
(projected gradient descent) is the default; CW gives smaller
perturbation at higher compute cost. Example with `torchattacks`:

```python
import torchattacks, torch
model.eval()
# PGD: eps=4/255 is a strong default for CIFAR-scale models;
# eps=8/255 is the AutoAttack benchmark setting; for larger
# images (ImageNet) start at eps=2/255 and tune.
atk = torchattacks.PGD(model, eps=4/255, alpha=1/255, steps=40)
adv = atk(images, labels)
# Measure: how many predictions flipped?
flipped = (model(adv).argmax(1) != labels).float().mean()
```

Save `clean[i]`, `adv[i]`, the predicted label on each, and the
L_inf delta per sample. One image where the clean label and adv
label differ is the proof.

### Variant B — Grey-box: query-based with logits

API returns confidences. Use `foolbox` with the `blackbox` interface
pointed at your API. SquareAttack and ZOO work well:

```python
import foolbox as fb
# Thin wrapper so foolbox treats the API as a model
class APIModel:
    def __call__(self, x):
        return call_api(x)  # returns logits tensor
atk = fb.attacks.LinfSquareAttack(steps=5000, p=0.05)
adv, _, success = atk(APIModel(), x, labels, epsilons=[4/255])
```

Budget-aware: SquareAttack typically needs 1k-10k queries per
sample. Share a query budget with the operator; attack 5 samples
hard before 50 samples lightly.

### Variant C — Black-box: transfer attack

API returns labels only. Train or download a substitute model with
similar architecture, run Variant A on the substitute, submit the
adversarial examples to the target. Transfer success rate is 20-80%
depending on arch similarity.

Pipeline:
1. Fingerprint the target architecture family from
   `model-extraction` / `ai-recon` (ResNet vs ViT vs CLIP matter).
2. Spin up a public pretrained substitute of the same family.
3. Generate PGD adversarial examples on the substitute.
4. Submit to the target, record the flip rate.

### Variant D — Physical patch (CV only)

For physical-world attacks (face recognition evasion, stop-sign
misclassification), craft an adversarial patch that stays effective
under lighting / angle / print variations. `torchattacks` has
`PatchAttack`; the Expectation over Transformations (EoT) framing
makes the patch robust to the physical gap. Scope often restricts
this to lab setup — do not deploy to a production physical
sensor without explicit authorization.

### Variant E — Non-CV modalities

- **Speech-to-text**: `torchattacks` doesn't cover audio; use the
  Carlini audio attack (`Audio Adversarial Examples` reference
  implementation if the operator ships it, else craft via PGD on
  spectrogram). Target: specific transcription (benign audio →
  target command).
- **NLP classifier**: `textattack` — recipes `BAEGarg2019`,
  `TextFoolerJin2019` for sentiment / topic classifiers. Measure
  flip rate under a semantic-preservation constraint.
- **Tabular (fraud, IDS)**: evasion is often constrained
  (categorical features, integer counts). Use `aif360` or a hand-
  rolled constrained PGD. Report the minimum change in dollars /
  packet count that flips the decision.

## Verification Oracle

- **Flip evidence**: for each of ≥3 crafted samples, the clean
  classification and adversarial classification differ, documented
  via (clean_image, adv_image, clean_label, adv_label, confidence,
  L_inf). This is `confirmed`.
- **Human-indistinguishable constraint met**: a human reviewer the
  operator supplies cannot visually/audibly distinguish adv from
  clean on blind pairs. If the operator can't run a human review,
  the L_inf / semantic-preservation metric substitutes but downgrade
  confidence.
- **Transfer evidence** (Variant C): the attack success rate on the
  target meets a threshold the operator agreed (e.g. ≥30%).

Model-judgement ("looks adversarial") is never a confirmed
oracle — flip rate on operator-supplied ground-truth labels is.

## Post-Extraction Exit

Write the finding to `engagement/findings/<id>.json`:
- CWE-20 / CWE-1039 (Inadequate Input Validation / ML)
- OWASP ML Top 10 (ML01: Input Manipulation)
- MITRE ATLAS: AML.T0043 (Craft Adversarial Data)
- AI-300 module: 10 (defensive-ML coverage)

STOP and return to the orchestrator with:
- Modality + access mode + attack class
- Flip rate on the sample set
- Perturbation magnitude required
- Follow-ups:
  - Confirmed evasion of a decision-critical classifier → report
    with impact description; the operator may want to chain with
    `supply-chain-attacks` to persist the adversarial pattern.
  - Transfer attack succeeded → `model-extraction` to probe
    further behavioral match with the substitute.

## Troubleshooting

### White-box attack flips <5% of samples

Model is adversarially-trained (robust by design) or the sample
set is already near the decision boundary. Raise `eps`, use CW
instead of PGD, and verify the model isn't in eval mode with
BatchNorm fused incorrectly. Record robustness as a *good*
finding — the model is resistant.

### Black-box queries hit rate limits

Expected on large-image / large-batch SquareAttack. Reduce `steps`,
batch samples, and spread queries across time. Record what budget
would have been needed to break the model.

### Transfer attack succeeds on substitute but fails on target

Substitute architecture doesn't match. Re-fingerprint via
`model-extraction` + `ai-recon`, swap substitute family (ResNet →
ViT or vice versa), re-run. Transfer rates below 10% usually mean
the architecture family is wrong.
