# Coffee Loyalty Web App

A Flask web application for managing digital coffee loyalty cards across multiple cafes.

## Features

- customer accounts with QR-based loyalty cards
- staff scanning and reward redemption
- manager tools for staff, invites, customers, and notes
- cafe owner protection
- global admin controls for cafes, users, and settings
- email verification, password reset, and onboarding emails
- branded cafe pages with slug URLs like `/<cafename>/`

## Tech Stack

- Python
- Flask
- SQLAlchemy
- SQLite
- Jinja templates

## Run the Project

1. Install the required Python packages.
2. Run `app.py`.
3. Open the local Flask URL in your browser.

The app creates its database tables automatically and includes lightweight SQLite schema migrations on startup.

## Important Accounts

- the seeded global admin account is `admin@local`
- the protected super-admin account cannot be deleted, suspended, or demoted

## Main Areas

- customer pages: QR code, loyalty card, account, history
- staff pages: scan, search, create customer
- manager pages: staff, invites, audit, customers, cafe settings
- admin pages: users, cafes, global settings

## Project Files

- [app.py](C:\Users\think\Documents\GitHub\2026-Yr12-tatehk-PWA-assessment\app.py): main Flask app, routes, helpers, and migrations
- [models.py](C:\Users\think\Documents\GitHub\2026-Yr12-tatehk-PWA-assessment\models.py): database models
- [templates](C:\Users\think\Documents\GitHub\2026-Yr12-tatehk-PWA-assessment\templates): HTML pages and email templates
- [TECHNICAL_DOCUMENTATION.md](C:\Users\think\Documents\GitHub\2026-Yr12-tatehk-PWA-assessment\TECHNICAL_DOCUMENTATION.md): technical overview of the system

## Notes

- this project uses role-based access control
- cafes must be archived before they can be permanently deleted
- customer suspension is handled per cafe

