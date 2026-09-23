# Project Management Service 📁

The Project Management Service is a microservice in the PII Redaction Platform that enables users to create and manage redaction projects. These projects define how personal data is identified and redacted across various services.

## Features 🚀

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

## Tech Stack 🛠️

- **Language:** Python
- **Framework:** FastAPI
- **Validation:** Pydantic
- **Database:** MongoDB
- **Service Discovery:** Consul
- **Containerization:** Docker

## Usage ✅

This service is consumed by:

- **Instant Redaction Service** – for immediate redaction of user input
- **Batch Redaction Worker** – for processing large files