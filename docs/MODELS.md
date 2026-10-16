# Model adapters

TextForensics keeps heavyweight detectors optional. Model weights are not committed to the repository or bundled in the default package/image.

## Design rules

- immutable upstream revisions;
- explicit model/checkpoint identity in detector evidence;
- safe `safetensors` loading where supported;
- `trust_remote_code=False`;
- local/offline operation after cache population;
- native scores are not automatically called calibrated probabilities;
- model adapters remain experimental until TextForensics produces its own held-out benchmark evidence.

## Desklib supervised-transformer adapter

Detector ID:
`desklib/ai-text-detector-v1.01`

Method family:
`supervised-transformer`

Model:
`desklib/ai-text-detector-v1.01`

Pinned revision:
`5fdea974cd4287c61674951ec78803aa274e2fb7`

Expected model-weight SHA-256:
`c024a1704c65f5a4bffeda58745c58fc0ed67d6ca07b158b068a257238815265`

License:
MIT

Upstream:
https://huggingface.co/desklib/ai-text-detector-v1.01

The adapter reconstructs the published DeBERTa-v3-large + attention-mask mean pooling + one-logit linear classification architecture. The model's sigmoid output remains a **native model score** inside TextForensics. TextForensics does not call it an independently calibrated authorship probability.

Default native threshold: 0.5.

TextForensics still requires held-out calibration/benchmark evidence before making product-level accuracy claims.

## Qwen Raw Alignment Imprint adapter

Detector ID:
`textforensics/qwen2.5-0.5b-rai`

Method family:
`alignment-likelihood`

Base model:
`Qwen/Qwen2.5-0.5B`

Base revision:
`060db6499f32faf8b98477b0a26969ef7d8b9987`

Base weight SHA-256:
`88c142557820ccad55bb59756bfcfcf891de9cc6202816bd346445188a0ed342`

Aligned model:
`Qwen/Qwen2.5-0.5B-Instruct`

Aligned revision:
`7ae557604adf67be50417f59c2c2f167def9a775`

Aligned weight SHA-256:
`fdf756fa7fcbe7404d5c60e26bff1a0c8b8aa1f72ced49e7dd0210fe288fb7fe`

License:
Apache-2.0 for both model repositories.

The adapter computes:

`RAI = mean_token_logP_aligned(text) - mean_token_logP_base(text)`

This is the Raw Alignment Imprint concept described in the 2026 Alignment Imprint/LAPD work. TextForensics deliberately labels this implementation **RAI**, not LAPD: it does not implement LAPD's information weighting and perturbation-based standardization.

The lightweight Qwen pair is an engineering choice for open licensing and manageable local resource use. It is **not** the paper's default evaluated Llama pair, so published LAPD/RAI performance numbers must not be transferred to this adapter.

The adapter emits a continuous score and `abstain` categorical verdict until a threshold is independently calibrated and validated for this exact pair.

Research reference:
https://arxiv.org/abs/2604.16923

## Model cache and offline operation

Model-specific cache environment variables:
- `TEXTFORENSICS_DESKLIB_CACHE_DIR`
- `TEXTFORENSICS_RAI_CACHE_DIR`

Offline switches:
- `TEXTFORENSICS_DESKLIB_OFFLINE=1`
- `TEXTFORENSICS_RAI_OFFLINE=1`

Device controls:
- `TEXTFORENSICS_DESKLIB_DEVICE=auto|cpu|cuda|xpu|mps`
- `TEXTFORENSICS_RAI_DEVICE=auto|cpu|cuda|xpu|mps`

For production containers, mount a persistent writable cache and keep the application root filesystem read-only.

## Integrity

Pinned revisions prevent branch drift. The expected weight hashes are recorded in adapter evidence and this document.

The current adapters rely on the Hugging Face cache/downloader to retrieve the pinned revisions. A future model-cache verifier will enforce weight hashes before loading from externally populated caches.

## Benchmark status

Real-weight CPU CI verifies that both adapters can download, load, and execute their pinned model artifacts. That is a **runtime integration test**, not a detector-accuracy benchmark.

Scientific release requires held-out RAID/DetectRL/M4 evaluation, low-FPR operating points, confidence intervals and slice analysis.
