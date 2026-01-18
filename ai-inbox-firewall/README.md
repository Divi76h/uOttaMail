# AI Inbox Firewall (SAM + Solace + Django + React)

This repo is a runnable full-stack starter that shows how to use **Solace Agent Mesh (SAM)** in a real app (not just a chat UI).

Core idea:
- Your app publishes events to Solace topics (Django does this)
- SAM’s **Event Mesh Gateway** subscribes to those topics and fans out the same event to multiple specialist agents
- Each agent outputs a new event to its own topic
- Django consumes the agent outputs, stores them, and pushes real-time updates to the UI (SSE)

## What’s included
- Solace PubSub+ broker (Docker)
- SAM project (Docker) with:
  - Event Mesh Gateway
  - SpamAgent, PriorityAgent, SummaryAgent, ActionItemsAgent
- Django API (Docker) with a simple “mock email system” (users can send emails to each other)
- React UI (Docker)

## Topic contract
- `email/new/<user_id>/<email_id>`
- `email/spam_classified/<user_id>/<email_id>`
- `email/priority_assigned/<user_id>/<email_id>`
- `email/summary/<user_id>/<email_id>`
- `email/action_items/<user_id>/<email_id>`

## Quickstart
### 1) Configure env
Copy env files:
- `cp .env.example .env`
- `cp sam/.env.example sam/.env`

Edit:
- `.env`: Django secret, Postgres settings (defaults fine)
- `sam/.env`: set `LLM_SERVICE_API_KEY` and model names

### 2) Start everything
```bash
docker compose up --build
```

Note: on the very first run, the `sam` container installs the **Event Mesh Gateway** plugin via
`sam plugin add ...` (it is not a pip package).

### 3) Open services
- React UI: http://localhost:5173
- Django API: http://localhost:8001/api/
- Solace Broker Manager: http://localhost:8080  (admin / admin)

This starter does **not** run the SAM chat Web UI by default (it runs only the agents + event-mesh gateway).

## How to demo
1. Register 2 users in the UI
2. Send an email from user A to user B
3. The email is published to `email/new/...`
4. Agents publish their outputs back to topics
5. Django consumer updates the email row and SSE pushes changes to the UI

## Layout
- `backend/` Django + consumer
- `frontend/` React app
- `sam/` Agent Mesh project (configs + python tools)
