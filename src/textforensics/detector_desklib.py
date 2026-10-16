from __future__ import annotations

import importlib.util
import os
import threading
import time
from dataclasses import dataclass
from typing import Any

from .detectors import DetectorPrediction


MODEL_ID = "desklib/ai-text-detector-v1.01"
MODEL_REVISION = "5fdea974cd4287c61674951ec78803aa274e2fb7"
MODEL_WEIGHTS_SHA256 = "c024a1704c65f5a4bffeda58745c58fc0ed67d6ca07b158b068a257238815265"
MODEL_LICENSE = "MIT"
DETECTOR_VERSION = f"1.01@{MODEL_REVISION[:12]}"

_RUNTIME_LOCK = threading.Lock()
_RUNTIME_CACHE: dict[tuple[str, str | None, bool], "_Runtime"] = {}


def _missing_dependencies() -> list[str]:
    required = ("torch", "transformers", "sentencepiece")
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


def _env_float(name: str, default: float, *, minimum: float, maximum: float) -> float:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        value = float(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be numeric.") from exc
    if not minimum <= value <= maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}.")
    return value


@dataclass(slots=True)
class _Runtime:
    torch: Any
    tokenizer: Any
    model: Any
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
            "TEXTFORENSICS_DESKLIB_DEVICE must be auto, cpu, cuda, xpu, or mps."
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
    import torch.nn as nn
    from transformers import AutoConfig, AutoModel, AutoTokenizer, PreTrainedModel

    device, device_name = _select_device(torch, requested_device)

    config = AutoConfig.from_pretrained(
        MODEL_ID,
        revision=MODEL_REVISION,
        cache_dir=cache_dir,
        local_files_only=offline,
        trust_remote_code=False,
    )

    class DesklibAIDetectionModel(PreTrainedModel):
        config_class = AutoConfig

        def __init__(self, model_config):
            super().__init__(model_config)
            self.model = AutoModel.from_config(model_config)
            self.classifier = nn.Linear(model_config.hidden_size, 1)
            self.init_weights()

        def forward(self, input_ids, attention_mask=None, labels=None):
            outputs = self.model(
                input_ids=input_ids,
                attention_mask=attention_mask,
            )
            last_hidden_state = outputs[0]
            if attention_mask is None:
                attention_mask = torch.ones(
                    last_hidden_state.shape[:2],
                    dtype=torch.long,
                    device=last_hidden_state.device,
                )
            expanded = (
                attention_mask.unsqueeze(-1)
                .expand(last_hidden_state.size())
                .float()
            )
            sum_embeddings = torch.sum(last_hidden_state * expanded, dim=1)
            sum_mask = torch.clamp(expanded.sum(dim=1), min=1e-9)
            pooled_output = sum_embeddings / sum_mask
            return {"logits": self.classifier(pooled_output)}

    tokenizer = AutoTokenizer.from_pretrained(
        MODEL_ID,
        revision=MODEL_REVISION,
        cache_dir=cache_dir,
        local_files_only=offline,
        trust_remote_code=False,
    )
    model = DesklibAIDetectionModel.from_pretrained(
        MODEL_ID,
        revision=MODEL_REVISION,
        cache_dir=cache_dir,
        local_files_only=offline,
        config=config,
        use_safetensors=True,
    )
    model.to(device)
    model.eval()
    return _Runtime(
        torch=torch,
        tokenizer=tokenizer,
        model=model,
        device=device,
        device_name=device_name,
    )


class DesklibDetector:
    detector_id = MODEL_ID
    detector_version = DETECTOR_VERSION
    detector_family = "supervised-transformer"

    def __init__(
        self,
        *,
        device: str | None = None,
        cache_dir: str | None = None,
        offline: bool | None = None,
        max_length: int | None = None,
        threshold: float | None = None,
        min_words: int | None = None,
    ):
        missing = _missing_dependencies()
        if missing:
            joined = ", ".join(missing)
            raise RuntimeError(
                "Desklib detector dependencies are missing "
                f"({joined}). Install the 'desklib' optional extra and, on "
                "platforms where PyTorch is not available from PyPI, install "
                "PyTorch from the official PyTorch wheel index first."
            )

        self.requested_device = (
            device
            if device is not None
            else os.getenv("TEXTFORENSICS_DESKLIB_DEVICE", "auto")
        )
        self.cache_dir = (
            cache_dir
            if cache_dir is not None
            else os.getenv("TEXTFORENSICS_DESKLIB_CACHE_DIR") or None
        )
        self.offline = (
            offline
            if offline is not None
            else _env_bool("TEXTFORENSICS_DESKLIB_OFFLINE", False)
        )
        self.max_length = (
            max_length
            if max_length is not None
            else _env_int(
                "TEXTFORENSICS_DESKLIB_MAX_LENGTH",
                768,
                minimum=64,
                maximum=4096,
            )
        )
        self.threshold = (
            threshold
            if threshold is not None
            else _env_float(
                "TEXTFORENSICS_DESKLIB_THRESHOLD",
                0.5,
                minimum=0.0,
                maximum=1.0,
            )
        )
        self.min_words = (
            min_words
            if min_words is not None
            else _env_int(
                "TEXTFORENSICS_DESKLIB_MIN_WORDS",
                80,
                minimum=1,
                maximum=10000,
            )
        )
        if not 64 <= int(self.max_length) <= 4096:
            raise ValueError("max_length must be between 64 and 4096.")
        if not 0.0 <= float(self.threshold) <= 1.0:
            raise ValueError("threshold must be between 0 and 1.")
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

    def _predict_score(self, text: str) -> tuple[float, str]:
        runtime = self._runtime()
        with self._inference_lock:
            encoded = runtime.tokenizer(
                text,
                padding="max_length",
                truncation=True,
                max_length=self.max_length,
                return_tensors="pt",
            )
            input_ids = encoded["input_ids"].to(runtime.device)
            attention_mask = encoded["attention_mask"].to(runtime.device)
            with runtime.torch.no_grad():
                outputs = runtime.model(
                    input_ids=input_ids,
                    attention_mask=attention_mask,
                )
                score = runtime.torch.sigmoid(outputs["logits"]).item()
        return float(score), runtime.device_name

    def detect(self, text: str) -> DetectorPrediction:
        started = time.perf_counter()
        word_count = len(text.split())
        if word_count < self.min_words:
            prediction = DetectorPrediction(
                schema="textforensics.detector-result/v1",
                detector_id=self.detector_id,
                detector_version=self.detector_version,
                detector_family=self.detector_family,
                execution="local",
                score=None,
                score_semantics=(
                    "higher_means_more_machine_like; native sigmoid classifier "
                    "score from the pinned Desklib model; not independently "
                    "calibrated by TextForensics"
                ),
                verdict="abstain",
                threshold=self.threshold,
                calibrated_ai_probability=None,
                calibration_id=None,
                reliability=None,
                supported_languages=["en"],
                min_words=self.min_words,
                evidence=[
                    {
                        "model_id": MODEL_ID,
                        "model_revision": MODEL_REVISION,
                        "model_weights_sha256": MODEL_WEIGHTS_SHA256,
                        "model_license": MODEL_LICENSE,
                    }
                ],
                warnings=[
                    (
                        "Text is below the TextForensics conservative minimum "
                        f"of {self.min_words} words for this adapter."
                    )
                ],
                runtime_ms=round((time.perf_counter() - started) * 1000, 3),
            )
            return prediction.validate(detector=self)

        score, device_name = self._predict_score(text)
        verdict = "ai_like" if score >= self.threshold else "human_like"
        prediction = DetectorPrediction(
            schema="textforensics.detector-result/v1",
            detector_id=self.detector_id,
            detector_version=self.detector_version,
            detector_family=self.detector_family,
            execution="local",
            score=round(score, 6),
            score_semantics=(
                "higher_means_more_machine_like; native sigmoid classifier "
                "score from the pinned Desklib model; not independently "
                "calibrated by TextForensics"
            ),
            verdict=verdict,
            threshold=float(self.threshold),
            calibrated_ai_probability=None,
            calibration_id=None,
            reliability=None,
            supported_languages=["en"],
            min_words=self.min_words,
            evidence=[
                {
                    "model_id": MODEL_ID,
                    "model_revision": MODEL_REVISION,
                    "model_weights_sha256": MODEL_WEIGHTS_SHA256,
                    "model_license": MODEL_LICENSE,
                    "device": device_name,
                    "max_length_tokens": int(self.max_length),
                    "native_threshold": float(self.threshold),
                }
            ],
            warnings=[
                (
                    "The detector score is the model's native sigmoid output. "
                    "TextForensics does not treat it as a calibrated authorship "
                    "probability without a separate held-out calibration artifact."
                ),
                "The pinned model declares English-language use.",
            ],
            runtime_ms=round((time.perf_counter() - started) * 1000, 3),
        )
        return prediction.validate(detector=self)
