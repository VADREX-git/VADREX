# Third-party notices

This repository distributes its own source only. The components below are fetched at build or run
time from their upstream registries; none of their source is vendored here. Versions are those
resolved by `package-lock.json`, `eval/plot/requirements.txt`, and the image digests pinned in
`docker-compose.yml` and `docker/`.

## Node packages (direct dependencies)

| Package | Version | License |
|---|---|---|
| `@noble/hashes` | 1.3.2 | MIT |
| `@nomicfoundation/hardhat-chai-matchers` | ^2.0.7 | MIT |
| `@nomicfoundation/hardhat-ethers` | 3.1.3 | MIT |
| `@nomicfoundation/hardhat-network-helpers` | 1.1.2 | MIT |
| `@nomicfoundation/hardhat-toolbox` | ^5.0.0 | MIT |
| `@openzeppelin/contracts` | 5.6.1 | MIT |
| `@types/better-sqlite3` | 7.6.11 | MIT |
| `@types/node` | 20.19.43 | MIT |
| `better-sqlite3` | 11.1.2 | MIT |
| `ethers` | 6.17.0 | MIT |
| `hardhat` | 2.28.6 | MIT |
| `ts-node` | 10.9.2 | MIT |
| `tsx` | 4.23.0 | MIT |
| `typescript` | 5.9.3 | Apache-2.0 |
| `vitest` | 2.1.9 | MIT |

Transitive dependencies are resolved by `package-lock.json`; run `npm ls --all` for the full tree.

## Container images

| Image | Pinned digest | License |
|---|---|---|
| `node` (Debian bookworm) | `sha256:8f693eaa…c9ba5` | MIT (Node.js); Debian base under its own mixed licenses |
| `orthancteam/orthanc` | `sha256:83a1f988…e0aee` | **GPL-family** — see below |
| `alpine/openssl` | `sha256:0b22ba3a…83cff` | Apache-2.0 (OpenSSL 3.x); Alpine base under its own licenses |
| `python` (slim) | `sha256:6b3223eb…2b740` | PSF License; Debian base under its own licenses |

**Orthanc.** Orthanc and its DICOMweb plugin are distributed under GPL-family terms by the Orthanc
project. This repository does not modify, link against, or redistribute Orthanc. It references the
official published image by digest and configures it through `config/orthanc-*/orthanc.json`; the
image is pulled from Docker Hub by the user at run time. Anyone redistributing the image itself must
comply with its license.

## Python packages (figure generation)

Pinned exactly in `eval/plot/requirements.txt` and installed inside `docker/Dockerfile.plot`:

| Package | Version | License |
|---|---|---|
| `matplotlib` | 3.11.0 | Matplotlib License (PSF-based, BSD-compatible) |
| `pandas` | 3.0.3 | BSD-3-Clause |
| `numpy` | 2.5.1 | BSD-3-Clause |
| `contourpy` | 1.3.3 | BSD-3-Clause |
| `cycler` | 0.12.1 | BSD-3-Clause |
| `fonttools` | 4.63.0 | MIT |
| `kiwisolver` | 1.5.0 | BSD-3-Clause |
| `packaging` | 26.2 | Apache-2.0 / BSD-2-Clause |
| `pillow` | 12.3.0 | MIT-CMU |
| `pyparsing` | 3.3.2 | MIT |
| `python-dateutil` | 2.9.0.post0 | Apache-2.0 / BSD-3-Clause |
| `six` | 1.17.0 | MIT |
| `tzdata` | 2026.3 | Apache-2.0 |

## Standards and specifications

The log tree follows RFC 6962 (Certificate Transparency). DICOM and DICOMweb are standards of the
DICOM Standards Committee. Neither is redistributed here.

## Sample data

No third-party medical images are included or downloaded. All DICOM used by the demos and the
evaluation is generated locally by `scripts/make-sample-dicom.ts` and `eval/src/dicom.ts`. Earlier
revisions downloaded a pydicom test file at run time; that dependency was removed.
