# Project Management Service

The Project Management Service is a microservice in the PII Redaction Platform that enables users to create and manage redaction projects. These projects define how personal data is identified and redacted across various services.

## Features

- **Project Management**
  - Create new redaction projects
  - Update existing projects
  - Delete projects
  - Retrieve all projects
  - Retrieve specific projects by ID

- **Redaction Configuration**
  - Support for both predefined and custom entity definitions
  - Specify redaction type (replace, mask, hash)
  - Retrieve list of supported predefined entities

## Tech stack

- **Language:** Python
- **Framework:** FastAPI
- **Validation:** Pydantic
- **Database:** PostgreSQL (SQLAlchemy, Alembic migrations)
- **Events:** Redis (`ai-gateway:project-changed`, evicts the redaction service's project cache)
- **Containerization:** Docker

## Used by

This service is consumed by:

- **Instant Redaction Service**, which redacts text, JSON and files with the project's settings
- The guardrail platform's dev bootstrap and `ai-gateway-credentials`, which create a project and a `service` API key

See [../README.md](../README.md).