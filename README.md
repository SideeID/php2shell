# php2shell scanner (Bun 1.4)

This is a Bun/TypeScript port of the Python scanner in the parent directory.
It keeps the same crafted multipart bodies, differential crash signals,
version fallback, phpMyAdmin retargeting, rejected-status handling, and exit
codes. Redirects are not followed.

## Run

```sh
bun run scanner.ts -u https://example.com
bun run scanner.ts -l hosts.txt -t 20 -o results.json --all-results
bun run scanner.ts -u https://example.com -H "Authorization: Bearer token" --sapi fpm
```

Use `-k` to disable TLS certificate verification. Only scan hosts you are
authorized to test: each target can receive up to roughly 29 MiB of crafted
multipart data.

## Porting notes

- `fetch` replaces the Python `h11` transport and `asyncio` upload loop.
- `AbortController` enforces the per-request timeout.
- Bun's fetch automatically handles response content decoding; the scanner
  streams the response and retains at most 1 MiB, cancelling the reader once
  that limit is reached.
- `--threads` controls concurrent asynchronous host workers, not OS threads.
- The Python progress bar is intentionally replaced by deterministic result
  output so this folder has no runtime dependency.

## Evidence fields

Each JSON result includes structured `signal`, `confidence`, and `warnings`
fields in addition to the original verdict fields. Dynamic fatal errors have
high confidence; differential worker failures and advertised unpatched
versions have medium confidence. A dynamic crash that conflicts with an
advertised fixed version is retained as `VULNERABLE` and includes a warning
about verifying `memory_limit` and vendor backports.

Run the focused tests with:

```sh
bun test
```
