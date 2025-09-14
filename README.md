# Millo Pay — Demo Payment System

This repository is a **demo** payment system called **Millo Pay**. It includes a frontend (React) and backend (Node.js + Express + Sequelize).
**This is a demo scaffold** intended for local testing and development. For production you must:
- Use HTTPS (TLS) with a valid certificate
- Use a production-grade DB (Postgres/MySQL) and rotate credentials securely
- Use a proper PCI-compliant payment processor for card handling — do not store raw PAN in production
- Conduct security audit and hardening before going live

## What is included
- `backend/` — Express API with user auth, simple fraud detection, encrypted card storage (AES), and SQLite demo DB.
- `frontend/` — Vite + React UI for registration, login, and making a payment.
- `.env.example` files and instructions.

## Quickstart (local demo)
Requirements: Node 18+, npm

1. Backend
```bash
cd backend
npm install
cp .env.example .env
# For demo the default uses SQLite. To use Postgres set DATABASE_URL in .env and change DB_DIALECT=postgres
npm run migrate
npm run start
```
Backend will run on port 5000 by default.

2. Frontend
```bash
cd frontend
npm install
npm run dev
```
Frontend runs on port 5173 by default and talks to the backend at http://localhost:5000 (CORS enabled).

## Production notes (short checklist)
- Terminate TLS at load balancer / reverse proxy (nginx, cloud LB)
- Use strong KMS for encryption keys (AWS KMS, GCP KMS)
- Use a PCI-compliant payment processor (Stripe, Adyen, Braintree) for card authorization — the demo **is not** PCI certified
- Add monitoring, WAF, and proper rate limits, IP and device fingerprinting for fraud
- Replace SQLite with Postgres, enable daily backups, and rotate DB credentials

---
This scaffold is provided "as-is" for demonstration and development purposes.
