# Third-party notices

Hosted browser PWA: Pyodide 0.29.5 / CPython 3.13.2 and included runtime components are distributed separately from the CLI. Original notices and source links are in [website/THIRD_PARTY.md](website/THIRD_PARTY.md) and the deployed license page. PNG/ICO app icons are color/background adaptations of the existing Lucide shield, with original notices retained. Generated runtime binaries are excluded from this GitHub checkout.

Runtime: Python standard library only; Python is installed separately, not redistributed here.

UI: four Lucide SVG icons (`shield-check`, `folder-open`, `download`, `rotate-ccw`).
Original license notices are included unchanged in
`src/download_inspector/web/assets/LUCIDE-LICENSE.txt` (ISC and inherited Feather MIT notices).
Source: https://lucide.dev/license

Development only: setuptools (build), Playwright (browser QA), Bandit (static analysis), GitHub Actions.
They are installed from their official registries during development/CI and are not vendored in this repository.
No third-party malware dataset, sample binary, proprietary antivirus signature, font, or stock image is included.

The application source has no reuse license assigned yet. These notices do not grant a license to the application's own code.
