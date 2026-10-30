# Windows HCL.CS on .NET 8

Follow [Windows local development](WINDOWS_NATIVE_SETUP.md) and
[HCL configuration](HCL_IAM_CONFIGURATION.md). Install the provider's required .NET 8
runtime separately. scripts/dev.py manages SBOM and preserves provider settings;
it does not install or migrate the external HCL.CS service.

Use `python scripts/dev.py --profile legacy --legacy-config windows`.
Keep approved HTTPS trust, registered redirects, provider CA bundle and existing
user/database data. Native Windows/.NET authentication remains untested; see the
[platform matrix](engineering/dev-launcher-platform-matrix.md).
