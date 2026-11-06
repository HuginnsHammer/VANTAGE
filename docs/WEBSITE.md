# VANTAGE public website

The public website is a static, dependency-free frontend served from the repository root through GitHub Pages.

## Local preview

From the repository root:

```fish
python -m http.server 8000
```

Open `http://127.0.0.1:8000`.

## Interactive exposure console

The console is a browser-only product preview. It currently supports:

- synthetic sample findings and asset inventory;
- overview metrics and severity distribution;
- finding search and severity/status filters;
- finding evidence and remediation inspection;
- importing a VANTAGE JSON report with a top-level `findings` array;
- exporting the current findings as CSV;
- resetting the sample workspace.

Import parsing and CSV generation happen locally in the browser. The website does not upload report contents or run security assessments. The sample data is illustrative and must never be presented as a real scan.

The importer accepts finding severities `critical`, `high`, `medium` and `low`. It normalizes common VANTAGE/CloudSentry report fields; it is a convenience preview, not a replacement for the canonical report parser.

## Deployment

The `.github/workflows/pages.yml` workflow validates HTML structure, required assets and JavaScript syntax on website pull requests. After changes reach `main`, it publishes the repository root to GitHub Pages.

Before the first deployment, a repository administrator must enable Pages once: open **Settings → Pages** at https://github.com/HuginnsHammer/VANTAGE/settings/pages, set **Build and deployment → Source** to **GitHub Actions**, and save if prompted. The workflow token can deploy to an enabled Pages site but does not have repository-administration permission to create the Pages site automatically. After this one-time setting is enabled, pushes to `main` run validation and deployment automatically. A custom domain can be configured later.

## Security and product boundaries

This is the public product website and local demo, not the authenticated VANTAGE control plane. It does not provide accounts, organization isolation, live scanning, domain verification, remote asset discovery or a backend API. Do not add a login/signup form until identity, session security, account lifecycle and server-side authorization are implemented.

Before connecting real assessments, build the authenticated API and use server-side authorization, validated scan scopes, durable jobs and tenant-aware persistence. Never treat a browser-only control as a security boundary.
