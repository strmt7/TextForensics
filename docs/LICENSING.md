# Licensing and commercial distribution

TextForensics source code is currently licensed under **AGPL-3.0-or-later**. See [LICENSE](../LICENSE).

## Commercial use

The AGPL does not prohibit commercial use. It is, however, a strong copyleft license with source-availability obligations, including specific requirements for modified versions used to provide network interaction.

This document is an engineering note, **not legal advice**. Organizations planning a commercial distribution or hosted offering should review the AGPL obligations with qualified counsel.

## Proprietary / dual-licensed offerings

Nothing in this repository currently grants a separate proprietary commercial license.

If the copyright holder(s) later want to offer a closed-source/dual-licensed commercial edition, that should be established explicitly through separate licensing terms and only when all relevant copyrights permit it.

Do not describe the current AGPL repository as "proprietary-commercial licensed" merely because it can be sold or used commercially.

## Third-party packages

The dependency-free core does not bundle third-party runtime packages, but optional surfaces install third-party dependencies such as FastAPI/Uvicorn and the MCP SDK.

Each dependency remains governed by its own license.

Before a commercial release:
- generate/review the dependency inventory;
- check license compatibility;
- retain required copyright/license notices;
- review transitive dependencies;
- archive the dependency versions used for the release.

## Detector plugins and model weights

Detector adapters/models are especially important licensing boundaries.

Every adapter should document:
- source-code license;
- model/checkpoint license;
- dataset-use restrictions where relevant;
- commercial-use restrictions if any;
- redistribution rights;
- whether weights are downloaded separately or bundled.

The core repository should not redistribute model weights merely because they are publicly downloadable.

## Data and benchmark licenses

RAID, DetectRL, M4, or other benchmark material should be obtained and used according to their own terms. Prefer dataset adapters/download instructions over copying large third-party corpora into this repository.

## Release review

The release checklist includes a licensing review. A technically green build is not sufficient for commercial distribution if a newly introduced dependency, model, dataset, or asset has incompatible terms.


## Bundled adapter model provenance

TextForensics source does **not** redistribute these model weights. Optional adapters download them separately from pinned upstream revisions.

### Desklib AI text detector v1.01
- model: `desklib/ai-text-detector-v1.01`
- license: MIT
- pinned revision: `5fdea974cd4287c61674951ec78803aa274e2fb7`
- expected `model.safetensors` SHA-256: `c024a1704c65f5a4bffeda58745c58fc0ed67d6ca07b158b068a257238815265`
- upstream: https://huggingface.co/desklib/ai-text-detector-v1.01

### Qwen2.5-0.5B RAI pair
- base model: `Qwen/Qwen2.5-0.5B`
- base license: Apache-2.0
- base revision: `060db6499f32faf8b98477b0a26969ef7d8b9987`
- base weight SHA-256: `88c142557820ccad55bb59756bfcfcf891de9cc6202816bd346445188a0ed342`
- aligned model: `Qwen/Qwen2.5-0.5B-Instruct`
- aligned license: Apache-2.0
- aligned revision: `7ae557604adf67be50417f59c2c2f167def9a775`
- aligned weight SHA-256: `fdf756fa7fcbe7404d5c60e26bff1a0c8b8aa1f72ced49e7dd0210fe288fb7fe`
- upstream: https://huggingface.co/Qwen/Qwen2.5-0.5B and https://huggingface.co/Qwen/Qwen2.5-0.5B-Instruct

A commercial distributor must re-check the upstream license and artifact identity at the pinned revisions before bundling or mirroring weights.
