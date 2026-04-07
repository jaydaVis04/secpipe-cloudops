# SecPipe-CloudOps

SecPipe-CloudOps is an extension of SecPipe, an existing Python security telemetry pipeline. The original SecPipe project ingests logs, normalizes events into a shared schema, runs detections, and exports structured findings. This version builds on that foundation and extends it into a simple cloud security operations workflow.

The goal is not to simulate a full enterprise platform. The goal is to show a realistic and explainable flow for multi-cloud findings:

`input -> normalize -> triage -> prioritize -> route to owner -> recommend remediation -> document -> deploy`

## What SecPipe Originally Was

SecPipe started as a modular security telemetry pipeline with:

- parser modules for different log sources
- a shared `Event` schema
- a detection engine that produces `Finding` records
- output modules for structured reporting

Those core ideas are still intact in this project. SecPipe-CloudOps reuses the same parser, pipeline, CLI, and output patterns instead of replacing them.

## What SecPipe-CloudOps Adds

SecPipe-CloudOps adds a cloud security triage workflow on top of the original SecPipe core:

- modeled cloud findings across AWS, GCP, Azure, and OCI
- a cloud findings parser that converts posture findings into SecPipe events
- cloud triage logic for classification, prioritization, and owner routing
- remediation ticket generation
- SOP and KB documentation in an internal-team style
- Docker packaging
- minimal Kubernetes manifests

## Project Story

This project is meant to support a credible interview explanation:

`I originally built SecPipe as a telemetry and detection pipeline. Then I extended it into SecPipe-CloudOps, where I modeled cloud security findings across AWS, GCP, Azure, and OCI, added triage and remediation workflows, mapped issues to owners, documented SOPs and knowledge base pages, and packaged the workflow for containerized and Kubernetes-based deployment.`

## Architecture Overview

```text
cloud/cloud_findings.json
        |
        v
secpipe.parsers.cloud_findings
        |
        v
Normalized SecPipe Event objects
        |
        v
secpipe.detections.cloud_triage
        |
        v
Structured triage Finding objects
        |
        v
secpipe.tickets.TicketGenerator
        |
        v
output/remediation_tickets.json
```

## Cloud Security Themes Covered

The sample findings and triage logic focus on practical cloud security issues:

- public storage bucket exposure
- excessive IAM permissions
- overly broad service account roles
- SSH open to the internet
- RDP exposed publicly
- insecure network paths
- misconfigured firewall-style controls
- ownership ambiguity
- remediation tracking and documentation

These are modeled lightly across four providers:

- AWS
- GCP
- Azure
- OCI

The project keeps the concepts consistent across providers without pretending to implement deep real-cloud integrations.

## Repo Structure

```text
secpipe/
  cli.py
  pipeline.py
  schema.py
  parsers/
  detections/
  outputs/
  tickets.py
cloud/
  cloud_findings.json
docs/
  SOP_public_bucket.md
  SOP_excessive_iam.md
  KB_triage_workflow.md
  KB_identifying_resource_owners.md
  ticket_template.md
k8s/
  namespace.yaml
  configmap.yaml
  deployment.yaml
  service.yaml
output/
  cloud_events.jsonl
  cloud_triage_findings.jsonl
  remediation_tickets.json
Dockerfile
```

## Local Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install -e .
```

## How to Run Locally

### 1. Ingest the modeled cloud findings

```bash
.venv/bin/python -m secpipe.cli ingest --source cloud --file cloud/cloud_findings.json --output output/cloud_events.jsonl
```

### 2. Run cloud triage

```bash
.venv/bin/python -m secpipe.cli triage --events output/cloud_events.jsonl --output output/cloud_triage_findings.jsonl
```

### 3. Generate remediation tickets

```bash
.venv/bin/python -m secpipe.cli tickets --findings output/cloud_triage_findings.jsonl --output output/remediation_tickets.json
```

### 4. Review the outputs

- [output/cloud_events.jsonl](/Users/jay/Code/secpipe-cloudops/output/cloud_events.jsonl)
- [output/cloud_triage_findings.jsonl](/Users/jay/Code/secpipe-cloudops/output/cloud_triage_findings.jsonl)
- [output/remediation_tickets.json](/Users/jay/Code/secpipe-cloudops/output/remediation_tickets.json)

## How the Cloud Triage Workflow Works

### Input

[cloud/cloud_findings.json](/Users/jay/Code/secpipe-cloudops/cloud/cloud_findings.json) contains realistic sample findings. Each record includes:

- `provider`
- `resource_id`
- `resource_type`
- `issue_type`
- `severity`
- `owner_team`
- `environment`
- `details`
- `recommended_action`

### Normalize

[secpipe/parsers/cloud_findings.py](/Users/jay/Code/secpipe-cloudops/secpipe/parsers/cloud_findings.py) converts each cloud finding into the existing SecPipe `Event` schema. Cloud-specific context is stored in `event.extra` so the project can reuse the original structure cleanly.

### Triage

[secpipe/detections/cloud_triage.py](/Users/jay/Code/secpipe-cloudops/secpipe/detections/cloud_triage.py) adds:

- classification
- service category
- severity and priority handling
- owner routing
- triage notes
- remediation guidance

### Remediation

[secpipe/tickets.py](/Users/jay/Code/secpipe-cloudops/secpipe/tickets.py) converts triage findings into ticket-like records with fields similar to Jira or ServiceNow, without integrating with those platforms directly.

### Documentation

The markdown files in [docs](/Users/jay/Code/secpipe-cloudops/docs) provide SOP and KB coverage for repeatable analyst response and remediation tracking.

## Docker

The project includes a simple [Dockerfile](/Users/jay/Code/secpipe-cloudops/Dockerfile) that installs the package and runs the existing CLI.

### Build

```bash
docker build -t secpipe-cloudops:latest .
```

### Run

```bash
docker run --rm secpipe-cloudops:latest --help
```

Example workflow command inside the container:

```bash
docker run --rm secpipe-cloudops:latest ingest --source cloud --file cloud/cloud_findings.json --output output/cloud_events.jsonl
```

Docker is used here to package the workflow consistently. It is not meant to imply a large production deployment model.

## Kubernetes

The repository includes minimal Kubernetes manifests in [k8s](/Users/jay/Code/secpipe-cloudops/k8s):

- `namespace.yaml`
- `configmap.yaml`
- `deployment.yaml`
- `service.yaml`

These manifests are intentionally simple. They show how the containerized workflow could be orchestrated with a Namespace, ConfigMap, Deployment, Pod, and Service. The Kubernetes layer is not the main purpose of the project.

Example apply sequence:

```bash
kubectl apply -f k8s/namespace.yaml
kubectl apply -f k8s/configmap.yaml
kubectl apply -f k8s/deployment.yaml
kubectl apply -f k8s/service.yaml
```

## Documentation Artifacts

The docs are written in a practical internal-team style:

- [docs/SOP_public_bucket.md](/Users/jay/Code/secpipe-cloudops/docs/SOP_public_bucket.md)
- [docs/SOP_excessive_iam.md](/Users/jay/Code/secpipe-cloudops/docs/SOP_excessive_iam.md)
- [docs/KB_triage_workflow.md](/Users/jay/Code/secpipe-cloudops/docs/KB_triage_workflow.md)
- [docs/KB_identifying_resource_owners.md](/Users/jay/Code/secpipe-cloudops/docs/KB_identifying_resource_owners.md)
- [docs/ticket_template.md](/Users/jay/Code/secpipe-cloudops/docs/ticket_template.md)

## What This Demonstrates In An Interview

This project supports an honest explanation that you:

- extended an existing Python security pipeline instead of rebuilding it
- modeled findings across AWS, GCP, Azure, and OCI
- understand basic IAM and least-privilege risk themes
- understand basic cloud network exposure themes
- can triage posture findings into actionable remediation steps
- can route issues to owners and document follow-up
- can package a Python workflow with Docker
- understand the role Kubernetes can play in container orchestration

## Scope and Honesty

This project does not claim:

- deep production multi-cloud deployment experience
- full enterprise CSPM coverage
- real Jira or ServiceNow integration
- real cloud control-plane automation
- advanced Kubernetes platform engineering

It is intentionally small, modular, and explainable.
