# Kali Executor Architecture

Status: implemented.

The backend and worker images are intentionally tool-free. All offensive and
analysis CLIs run inside `kali_runner`, which exposes a small HTTP API:

- `POST /jobs`
- `GET /jobs/{job_id}`
- `GET /jobs/{job_id}/result`
- `GET /profiles`
- `GET /tools`

The backend uses:

- `backend/app/services/kali_executor.py` for job dispatch and polling.
- `backend/app/services/kali_catalog.py` for live catalog mapping.
- `backend/app/services/tool_catalog.py` only as agent-facing tool narrative.

Tool availability means:

1. a canonical tool is mapped in `TOOL_TO_PROFILE`;
2. the profile is loaded by `kali_runner`;
3. the executable referenced by the profile exists in the Kali container.

Runtime installation from backend routes was removed. Adding a tool now means:

1. add/install it in `kali-runner/Dockerfile`;
2. create a safe YAML profile in `kali-runner/profiles`;
3. map canonical tool name to profile in `TOOL_TO_PROFILE`;
4. validate through `/api/kali-runner/catalog`.
