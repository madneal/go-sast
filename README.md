# go-sast

Minimal white-box scanner for hard-coded secrets in CI/CD. It checks Go source using the Go AST and scans common text/config formats for assignments to names such as `password`, `token`, `secret`, and `api_key`.

The scanner prints masked findings and exits with status 1 when `--fail-on-findings` is set. It is intended to run as a Cloud Build step against `/workspace`, not as a deployed application service.

## Cloud Build

The root `cloudbuild.yml` builds and pushes the scanner image to Artifact Registry. A consuming repository can then use that image as a Cloud Build step:

```yaml
- id: sast
  name: asia-southeast1-docker.pkg.dev/$PROJECT_ID/security-gate/go-sast:latest
  args: ["--path", "/workspace", "--fail-on-findings"]
```
