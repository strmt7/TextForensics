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
