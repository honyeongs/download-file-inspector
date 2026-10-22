# Security Policy

The public PWA is separate from the loopback development server: it analyzes files in the browser and serves only fixed public assets from a header-enforcing Worker. See [deployed security-fix verification](docs/SECURITY_FIXES_2026-10-22.md). The loopback-only restrictions below still apply to the Python server.

This is a local portfolio tool, not an antivirus, sandbox, security certification, or production multi-user upload service.

## Security boundaries

- Only `127.0.0.1` is bound. Do not expose it through port forwarding, a public reverse proxy, or `0.0.0.0`.
- Exact Host and same-origin POST checks mitigate DNS rebinding and cross-origin browser access. CORS is not enabled.
- The HTTP API accepts bytes, never a server filesystem path. Static files use an exact allowlist.
- No uploaded file is persisted, executed, extracted, or sent to a remote service. JSON export is explicit.
- Input, central-directory size, entry count, body time, and finding count are bounded.
- Untrusted values are rendered with `textContent`; control and bidi characters are made visible.
- A SHA-256 match means equality to a caller-supplied reference, not an authenticated publisher or absence of malware.

## Residual risks

The browser and Python runtime process untrusted metadata. Keep both updated.
The HTTP server is single-process and single-request: a local client can delay other local requests; it is not hardened for hostile multi-user environments.
Loopback is not authentication against other local users, native processes, browser extensions, or OS administrators.
The selected file may still be read by endpoint security or the OS. Memory is not securely erased after a request.
The snapshot is consistent for hash and analysis, but metadata checks cannot prove a live source file never changed during reading.
Filename-based rules have false positives and false negatives. CRC declarations are compared, but payload CRC is not computed.
Encrypted and nested payloads are opaque. ZIP64 central directories and multi-disk archives fail closed as unsupported.

## Reporting

Do not post real malicious files, credentials, personal filenames, or confidential reports in public issues.
Use GitHub private vulnerability reporting if the repository owner enables it; otherwise request a private channel from the owner without including exploit data.
There is no published response SLA.

## References

- [OWASP File Upload Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html)
- [Python zipfile documentation](https://docs.python.org/3/library/zipfile.html)
- [Python hashlib documentation](https://docs.python.org/3/library/hashlib.html)
- [PKWARE ZIP format specification](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)
