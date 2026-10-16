from __future__ import annotations

import importlib.util
import os
import threading
import time
from dataclasses import dataclass
from typing import Any

from .detectors import DetectorPrediction


BASE_MODEL_ID = "Qwen/Qwen2.5-0.5B"
BASE_MODEL_REVISION = "060db6499f32faf8b98477b0a26969ef7d8b9987"
BASE_WEIGHTS_SHA256 = "88c142557820ccad55bb59756bfcfcf891de9cc6202816bd346445188a0ed342"
ALIGNED_MODEL_ID = "Qwen/Qwen2.5-0.5B-Instruct"
ALIGNED_MODEL_REVISION = "7ae557604adf67be50417f59c2c2f167def9a775"
ALIGNED_WEIGHTS_SHA256 = "fdf756fa7fcbe7404d5c60e26bff1a0c8b8aa1f72ced49e7dd0210fe288fb7fe"
MODEL_LICENSE = "Apache-2.0"
DETECTOR_ID = "textforensics/qwen2.5-0.5b-rai"
DETECTOR_VERSION = (
    f"rai-qwen2.5-0.5b@{BASE_MODEL_REVISION[:8]}+{ALIGNED_MODEL_REVISION[:8]}"
)

_RUNTIME_LOCK = threading.Lock()
_RUNTIME_CACHE: dict[tuple[str, str | None, bool], "_Runtime"] = {}


def _missing_dependencies() -> list[str]:
    required = ("torch", "transformers")
    return [name for name in required if importlib.util.find_spec(name) is None]


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    value = raw.strip().lower()
    if value in {"1", "true", "yes", "on"}:
        return True
    if value in {"0", "false", "no", "off"}:
        return False
    raise ValueError(f"{name} must be a boolean value.")


def _env_int(name: str, default: int, *, minimum: int, maximum: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer.") from exc
    if not minimum <= value <= maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}.")
    return value


@dataclass(slots=True)
class _Runtime:
    torch: Any
    tokenizer: Any
    base_model: Any
    aligned_model: Any
    device: Any
    device_name: str


def _select_device(torch: Any, requested: str) -> tuple[Any, str]:
    requested = requested.strip().lower()
    if requested == "auto":
        if torch.cuda.is_available():
            requested = "cuda"
        elif hasattr(torch, "xpu") and torch.xpu.is_available():
            requested = "xpu"
        elif (
            hasattr(torch.backends, "mps")
            and torch.backends.mps.is_available()
        ):
            requested = "mps"
        else:
            requested = "cpu"

    if requested not in {"cpu", "cuda", "xpu", "mps"}:
        raise ValueError(
            "TEXTFORENSICS_RAI_DEVICE must be auto, cpu, cuda, xpu, or mps."
        )
    if requested == "cuda" and not torch.cuda.is_available():
        raise RuntimeError("CUDA was requested but is not available.")
    if requested == "xpu" and not (
        hasattr(torch, "xpu") and torch.xpu.is_available()
    ):
        raise RuntimeError("XPU was requested but is not available.")
    if requested == "mps" and not (
        hasattr(torch.backends, "mps") and torch.backends.mps.is_available()
    ):
        raise RuntimeError("MPS was requested but is not available.")
    return torch.device(requested), requested


def _build_runtime(
    *,
    requested_device: str,
    cache_dir: str | None,
    offline: bool,
) -> _Runtime:
    import torch
    from transformers import AutoModelForCausalLM, AutoTokenizer

    device, device_name = _select_device(torch, requested_device)
    common = {
        "cache_dir": cache_dir,
        "local_files_only": offline,
        "trust_remote_code": False,
        "use_safetensors": True,
    }

    tokenizer = AutoTokenizer.from_pretrained(
        BASE_MODEL_ID,
        revision=BASE_MODEL_REVISION,
        cache_dir=cache_dir,
        local_files_only=offline,
        trust_remote_code=False,
    )
    base_model = AutoModelForCausalLM.from_pretrained(
        BASE_MODEL_ID,
        revision=BASE_MODEL_REVISION,
        torch_dtype="auto",
        **common,
    )
    aligned_model = AutoModelForCausalLM.from_pretrained(
        ALIGNED_MODEL_ID,
        revision=ALIGNED_MODEL_REVISION,
        torch_dtype="auto",
        **common,
    )
    if base_model.config.vocab_size != aligned_model.config.vocab_size:
        raise RuntimeError("RAI model pair has incompatible vocabulary sizes.")
    if int(base_model.config.vocab_size) != len(tokenizer):
        raise RuntimeError("RAI tokenizer/model vocabulary mismatch.")

    base_model.to(device)
    aligned_model.to(device)
    base_model.eval()
    aligned_model.eval()
    return _Runtime(
        torch=torch,
        tokenizer=tokenizer,
        base_model=base_model,
        aligned_model=aligned_model,
        device=device,
        device_name=device_name,
    )


class QwenRAIDetector:
    """Raw Alignment Imprint detector using a pinned Qwen base/aligned pair.

    RAI is the mean token log-likelihood under the aligned model minus the
    corresponding mean token log-likelihood under the base model. Higher scores
    are expected to reflect stronger alignment imprint. This adapter deliberately
    abstains categorically until an independently fitted threshold is supplied by
    a future calibration-registry integration.
    """

    detector_id = DETECTOR_ID
    detector_version = DETECTOR_VERSION
    detector_family = "alignment-likelihood"

    def __init__(
        self,
        *,
        device: str | None = None,
        cache_dir: str | None = None,
        offline: bool | None = None,
        max_length: int | None = None,
        min_words: int | None = None,
    ):
        missing = _missing_dependencies()
        if missing:
            raise RuntimeError(
                "RAI detector dependencies are missing "
                f"({', '.join(missing)}). Install the 'rai' optional extra and, "
                "on platforms where PyTorch is not available from PyPI, install "
                "PyTorch from the official PyTorch wheel index first."
            )
        self.requested_device = (
            device
            if device is not None
            else os.getenv("TEXTFORENSICS_RAI_DEVICE", "auto")
        )
        self.cache_dir = (
            cache_dir
            if cache_dir is not None
            else os.getenv("TEXTFORENSICS_RAI_CACHE_DIR") or None
        )
        self.offline = (
            offline
            if offline is not None
            else _env_bool("TEXTFORENSICS_RAI_OFFLINE", False)
        )
        self.max_length = (
            max_length
            if max_length is not None
            else _env_int(
                "TEXTFORENSICS_RAI_MAX_LENGTH",
                768,
                minimum=64,
                maximum=4096,
            )
        )
        self.min_words = (
            min_words
            if min_words is not None
            else _env_int(
                "TEXTFORENSICS_RAI_MIN_WORDS",
                80,
                minimum=1,
                maximum=10000,
            )
        )
        if not 64 <= int(self.max_length) <= 4096:
            raise ValueError("max_length must be between 64 and 4096.")
        if int(self.min_words) < 1:
            raise ValueError("min_words must be at least 1.")
        self._inference_lock = threading.Lock()

    def _runtime(self) -> _Runtime:
        key = (self.requested_device, self.cache_dir, self.offline)
        with _RUNTIME_LOCK:
            runtime = _RUNTIME_CACHE.get(key)
            if runtime is None:
                runtime = _build_runtime(
                    requested_device=self.requested_device,
                    cache_dir=self.cache_dir,
                    offline=self.offline,
                )
                _RUNTIME_CACHE[key] = runtime
            return runtime

    @staticmethod
    def _mean_log_likelihood(
        runtime: _Runtime,
        model: Any,
        input_ids: Any,
        attention_mask: Any,
    ) -> float:
        torch = runtime.torch
        with torch.no_grad():
            logits = model(
                input_ids=input_ids,
                attention_mask=attention_mask,
                use_cache=False,
            ).logits
            shifted_logits = logits[:, :-1, :].float()
            targets = input_ids[:, 1:]
            mask = attention_mask[:, 1:].bool()
            if not bool(mask.any()):
                raise ValueError("RAI requires at least two scored tokens.")
            log_probs = torch.log_softmax(shifted_logits, dim=-1)
            token_log_probs = log_probs.gather(
                -1,
                targets.unsqueeze(-1),
            ).squeeze(-1)
            return float(token_log_probs.masked_select(mask).mean().item())

    def _score(self, text: str) -> tuple[float, float, float, str, int]:
        runtime = self._runtime()
        encoded = runtime.tokenizer(
            text,
            add_special_tokens=False,
            truncation=True,
            max_length=self.max_length,
            return_attention_mask=True,
            return_tensors="pt",
        )
        input_ids = encoded["input_ids"].to(runtime.device)
        attention_mask = encoded["attention_mask"].to(runtime.device)
        token_count = int(attention_mask.sum().item())
        if token_count < 2:
            raise ValueError("RAI requires at least two scored tokens.")

        with self._inference_lock:
            base_ll = self._mean_log_likelihood(
                runtime,
                runtime.base_model,
                input_ids,
                attention_mask,
            )
            aligned_ll = self._mean_log_likelihood(
                runtime,
                runtime.aligned_model,
                input_ids,
                attention_mask,
            )
        return (
            aligned_ll - base_ll,
            base_ll,
            aligned_ll,
            runtime.device_name,
            token_count,
        )

    def detect(self, text: str) -> DetectorPrediction:
        started = time.perf_counter()
        word_count = len(text.split())
        evidence = [
            {
                "method": "raw_alignment_imprint",
                "base_model_id": BASE_MODEL_ID,
                "base_model_revision": BASE_MODEL_REVISION,
                "base_weights_sha256": BASE_WEIGHTS_SHA256,
                "aligned_model_id": ALIGNED_MODEL_ID,
                "aligned_model_revision": ALIGNED_MODEL_REVISION,
                "aligned_weights_sha256": ALIGNED_WEIGHTS_SHA256,
                "model_license": MODEL_LICENSE,
            }
        ]

        if word_count < self.min_words:
            return DetectorPrediction(
                schema="textforensics.detector-result/v1",
                detector_id=self.detector_id,
                detector_version=self.detector_version,
                detector_family=self.detector_family,
                execution="local",
                score=None,
                score_semantics=(
                    "higher_means_more_machine_like; raw alignment imprint "
                    "(mean aligned-model token log-likelihood minus mean "
                    "base-model token log-likelihood); uncalibrated"
                ),
                verdict="abstain",
                threshold=None,
                calibrated_ai_probability=None,
                calibration_id=None,
                reliability=None,
                supported_languages=[],
                min_words=self.min_words,
                evidence=evidence,
                warnings=[
                    (
                        "Text is below the TextForensics conservative minimum "
                        f"of {self.min_words} words for this adapter."
                    )
                ],
                runtime_ms=round((time.perf_counter() - started) * 1000, 3),
            ).validate(detector=self)

        score, base_ll, aligned_ll, device_name, token_count = self._score(text)
        evidence[0].update(
            {
                "device": device_name,
                "max_length_tokens": int(self.max_length),
                "scored_tokens": token_count,
                "mean_base_log_likelihood": round(base_ll, 6),
                "mean_aligned_log_likelihood": round(aligned_ll, 6),
            }
        )
        return DetectorPrediction(
            schema="textforensics.detector-result/v1",
            detector_id=self.detector_id,
            detector_version=self.detector_version,
            detector_family=self.detector_family,
            execution="local",
            score=round(score, 6),
            score_semantics=(
                "higher_means_more_machine_like; raw alignment imprint "
                "(mean aligned-model token log-likelihood minus mean "
                "base-model token log-likelihood); uncalibrated"
            ),
            verdict="abstain",
            threshold=None,
            calibrated_ai_probability=None,
            calibration_id=None,
            reliability=None,
            supported_languages=[],
            min_words=self.min_words,
            evidence=evidence,
            warnings=[
                (
                    "RAI is emitted as a continuous uncalibrated statistic. "
                    "This adapter abstains categorically until TextForensics has "
                    "a separately validated threshold artifact for this exact "
                    "model pair and input regime."
                ),
                (
                    "This lightweight Qwen model pair is a commercial-safe "
                    "engineering choice, not the default model pair evaluated "
                    "in the LAPD paper; performance must be measured separately."
                ),
            ],
            runtime_ms=round((time.perf_counter() - started) * 1000, 3),
        ).validate(detector=self)
