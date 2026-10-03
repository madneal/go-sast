# go-sast

Minimal white-box scanner for hard-coded secrets. It checks Go source using the Go AST and scans common text/config formats for assignments to names such as `password`, `token`, `secret`, and `api_key`.

## API

`POST /scan` accepts source files and returns masked findings:

```json
{
  "files": [
    {"path": "config.yaml", "content": "password: hardcoded-value"}
  ]
}
```

The service exposes `GET /healthz` and listens on the Cloud Run `PORT` environment variable.

## Cloud Build

The root `cloudbuild.yml` builds the image, pushes it to Artifact Registry, and deploys the `go-sast` Cloud Run service. The GitHub Cloud Build trigger should point at this file and run on pushes to the default branch.
