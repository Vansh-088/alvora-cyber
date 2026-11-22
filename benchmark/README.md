# Prompt-attack detection benchmark

Two benchmarks live here:

| Script | Data | Purpose |
|---|---|---|
| `eval.js` (`npm test`) | 40 hand-written cases in `dataset.js` | Regression test for the rule engine. Scores 100%, which says nothing about real-world accuracy. |
| `eval-public.mjs` (`npm run benchmark:public`) | 2,976 prompts from three public labelled datasets | The real measurement, on data the detectors weren't written against. |

## Reproduce

```bash
npm run install:classifier          # once: fetch + checksum-verify + int8-quantize the model
node benchmark/fetch-public.mjs     # once: download eval + tuning datasets → benchmark/.cache/
node benchmark/tune-threshold.mjs   # pick threshold/veto on the TUNING set
npm run benchmark:public            # score on the held-out EVAL set
```

Classifier scores are cached in `benchmark/.cache/scores.json`, so re-runs are instant.

## Detectors

- **rules**: `backend/lib/promptInjectionGuard.js`, a regex engine.
- **classifier**: [`protectai/deberta-v3-base-prompt-injection-v2`](https://huggingface.co/protectai/deberta-v3-base-prompt-injection-v2) (Apache-2.0). It runs on-device through onnxruntime-node, quantized to int8 (739 MB → 244 MB). The int8 model agrees with fp32 on 99.6% of decisions (526 of 528 prompts; mean |Δscore| 0.006).
- **combined**: `fuse()` in `backend/lib/injectionClassifier.js`, which is what `/api/scan` uses:
  - A classifier score ≥ 0.1 holds the prompt for review.
  - When the rules and the classifier agree, the prompt is blocked.
  - When the rules only matched attack *phrasing* ("ignore previous instructions") and the classifier says benign (< 0.1), the result is a flag rather than a hold.

"Detected" means the prompt is blocked or held (BLOCK or REVIEW).

## Methodology

- **Eval set (held out):**
  - `deepset/prompt-injections` test split
  - `xTRam1/safe-guard-prompt-injection` test split
  - A deterministic 400 + 400 sample of `TrustAIRLab/in-the-wild-jailbreak-prompts` (Dec-2023 snapshot)
- **Tuning set (disjoint):**
  - deepset train split
  - SafeGuard train split (600)
  - In-the-wild May-2023 snapshot (300 + 300), with any text that also appears in the eval set removed
- **Excluded data:** `jackhhao/jailbreak-classification` is left out of both sets because the classifier was trained on it.
- **Threshold rule:** pick the most conservative value within 0.01 F1 of the best, with ≤ 1% false alarms on the clean-label sources. The veto uses the same principle and landed equal to the threshold (0.1).

## Results (held-out eval set, 2026-10-23)

| Detector | Dataset | n | Recall | Precision | F1 | False alarms |
|---|---|---:|---:|---:|---:|---:|
| rules | deepset | 116 | 8.3% | 100% | 0.154 | 0.0% |
| rules | SafeGuard | 2060 | 18.3% | 99.2% | 0.309 | 0.1% |
| rules | in-the-wild | 800 | 30.5% | 85.3% | 0.449 | 5.3% |
| **rules** | **all** | **2976** | **22.2%** | 91.8% | **0.357** | 1.2% |
| combined | deepset | 116 | 40.0% | 100% | 0.571 | 0.0% |
| combined | SafeGuard | 2060 | 88.2% | 98.6% | 0.931 | 0.6% |
| combined | in-the-wild | 800 | 78.5% | 77.3% | 0.779 | 23.0%\* |
| **combined** | **all** | **2976** | **82.1%** | 90.1% | **0.859** | 5.4%\* |

Latency is 10–40 ms for typical prompts. A 512-token window takes about 0.5 s on Apple Silicon in Low Power Mode, and long pastes are scanned as at most 3 windows (start, middle, end).

## Caveats (read these before quoting numbers)

- **\*In-the-wild "false alarms" are mostly label noise plus persona prompts.** A manual audit of 40 held-out cases found:
  - About 14 were real jailbreaks labelled "regular": DAN, Mongo Tom, "exception to AI ethical protocols", and a Chinese "forget your moral and legal restrictions".
  - About 21 were elaborate character or persona prompts (SillyTavern `{{char}}` cards, "act as a game host"). These are genuine false alarms; the model card warns that system-style prompts trigger it. They're **held** with a one-click "Send", never blocked.

  On ordinary prompts (the clean-label benign sets) false alarms are 0–0.6%.
- **English only.** 23 of deepset's 60 attacks are German; 12 of those were missed.
- **Jailbreaks.** The classifier targets injections. The "grandma exploit" family is covered by rule INJ-012, which matches none of the 4,557 public prompts, so it doesn't change these numbers.
- **Why not Prompt Guard 2?** Meta's Llama Prompt Guard 2 covers jailbreaks too, but downloads are gated behind manual license approval. If you accept the license on Hugging Face, it can be pointed at through `ALVORA_CLASSIFIER_DIR`. It uses the same DeBERTa-style tokenizer and a two-class head, but re-run `tune-threshold.mjs`, because its scores are calibrated differently.
