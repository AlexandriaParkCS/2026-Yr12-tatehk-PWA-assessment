# Technical Documentation

## Project Overview

This project is a Flask-based web application for managing digital coffee loyalty cards across multiple cafes. It supports customers, staff, cafe managers, cafe owners, and global administrators. The system combines authentication, cafe membership, QR-based loyalty scanning, reward redemption, email workflows, branding, and admin controls in a single web app.

The main goal of the system is to let customers keep a digital loyalty card while giving cafe staff and managers tools to operate that loyalty program efficiently.

## Architecture

The application uses a simple server-rendered architecture:

- `app.py` contains the Flask app factory, route handlers, helper functions, permission checks, email logic, and lightweight migration logic.
- `models.py` contains the SQLAlchemy database models.
- `templates/` contains Jinja HTML templates for all user-facing pages and HTML emails.
- SQLite is used as the database through SQLAlchemy.
- Bootstrap-style layout classes are used for responsive UI structure.

This is a monolithic architecture rather than a separated frontend/backend API architecture. That decision was made because it is easier to build, test, and explain for a school software engineering project while still supporting a full multi-role system.

## Core User Roles

- Customer: views their QR code, loyalty card, card history, and account details.
- Staff: scans customer QR codes, adds loyalty progress, redeems rewards, and creates customer accounts.
- Manager: manages staff, invites, customer notes, moderation actions, and cafe settings.
- Cafe Owner: same operational ability as a manager, but protected from removal by another manager.
- Global Admin: manages all cafes, users, global settings, and protected system-level actions.

## Main Components

### Authentication and Account Management

The authentication system includes:

- public registration
- login using username or email
- forgot password and reset password flows
- email verification before first login
- password setup links for staff/admin-created users
- account profile editing
- email change verification

Important routes include:

- `/register`
- `/login`
- `/forgot-password`
- `/reset-password/<token>`
- `/verify-email/<token>`
- `/account`

### Cafe and Membership System

The app is multi-cafe. A user can belong to more than one cafe, and each cafe has its own settings, staff, and loyalty cards.

Important routes include:

- `/select-cafe`
- `/<cafe_slug>/`
- `/<cafe_slug>/staff`
- `/<cafe_slug>/manager`
- `/<cafe_slug>/settings`
- `/admin/cafes`
- `/admin/create-cafe`

The slug-based URL system was chosen so each cafe feels like its own location in the app and links are easier to share and understand.

### Loyalty System

Each cafe has configurable loyalty settings. The system currently supports:

- stamp-based rewards
- points-based rewards

Important loyalty routes include:

- `/staff/lookup`
- `/staff/add-stamp-by-token`
- `/staff/redeem-by-token`
- `/card`
- `/card/history`
- `/card/status`

The loyalty logic is stored per cafe so different cafes can run different reward systems.

### Staff and Manager Tools

Managers can:

- add staff directly
- create and resend invites
- revoke invites
- update roles
- reset staff passwords by email
- search customers
- write notes and flags
- suspend or reactivate customers
- view customer history

Important routes include:

- `/manager/staff`
- `/manager/invites/create`
- `/manager/invites/revoke`
- `/manager/invites/resend`
- `/manager/customers`
- `/manager/customers/<user_id>`
- `/manager/customer-note`
- `/manager/customer-moderation`

### Global Admin Tools

Global admins can:

- create cafes
- edit, disable, archive, reopen, and delete cafes
- transfer cafe ownership
- manage users
- suspend, delete, and promote users
- manage blocked emails and phone numbers
- configure global settings and SMTP

Important routes include:

- `/admin/settings`
- `/admin/cafes`
- `/admin/users`
- `/admin/users/<user_id>`

## Key Database Models

### `User`

Stores account-level information:

- username
- email
- password hash
- verification and onboarding state
- active/admin flags
- QR token

### `Cafe`

Stores each cafe location:

- name
- slug
- active/archive state
- branding fields
- public page information

### `CafeMember`

Connects a user to a cafe with a role:

- staff
- manager
- owner

### `CafeSettings`

Stores per-cafe configuration:

- loyalty rules
- reward display settings
- staff permissions
- invite settings
- customer behaviour settings

### `LoyaltyCard`

Stores a customer’s progress for one cafe:

- stamps
- points
- reward availability
- last activity times

### `StaffInvite`

Stores invite links for staff and managers:

- invite email
- role
- token
- expiry
- accepted/revoked state

### `PasswordResetToken`

Stores one-time password reset or password setup links.

### `EmailVerificationToken`

Stores one-time email verification links for new accounts and email changes.

### `CafeCustomerNote`

Stores manager-only customer metadata for a specific cafe:

- note
- flag state
- suspension state
- suspension reason
- who updated it

### `BlockedContact`

Stores globally blocked emails or phone numbers.

## Permission Design

Role checks are enforced in backend route decorators and helper functions, not just in the UI. This was important so hidden buttons alone do not become the only security control.

Examples:

- `require_login` protects authenticated pages.
- `require_global_admin` protects admin-only pages.
- `require_role_in_cafe(...)` protects staff and manager actions.
- owner protection prevents managers from removing another cafe owner.
- protected super-admin logic prevents the seeded `admin@local` account from being deleted, suspended, or demoted.

This defence-in-depth approach was chosen to reduce the chance of privilege escalation bugs.

## Email System

The email system uses SMTP settings stored in global settings. It supports:

- password reset emails
- password setup emails
- invite emails
- added-to-cafe emails
- email verification emails

HTML email templates are stored in `templates/emails/`.

This feature was included because it makes the system behave more like a real product instead of a classroom-only prototype.

## Error Handling and Safety

The project includes:

- custom `403`, `404`, and `500` pages
- CSRF protection on forms
- token expiry for password and verification links
- blocked contact checks
- protected super-admin restrictions
- archived-before-delete behaviour for cafes
- customer suspension controls at cafe level

These choices improve robustness and show consideration of real-world misuse and failure cases.

## Database Migration Approach

Earlier in development, adding new model fields could break an existing SQLite database because `db.create_all()` does not update old tables. To fix this, the project now includes a lightweight migration system in `app.py`.

This migration system:

- creates a `schema_migrations` table
- checks which migrations have already run
- applies missing SQLite `ALTER TABLE` updates safely on startup

This was chosen as a practical solution for the assignment because it improves maintainability without introducing a full migration framework.

## Important Design Decisions

### 1. Server-rendered Flask app instead of SPA

Reason:

- simpler to develop and explain
- fewer moving parts
- easier role-based routing with Jinja templates

### 2. Slug-based cafe URLs

Reason:

- better user experience
- cleaner links
- easier to treat each cafe as its own space

### 3. Per-cafe membership model

Reason:

- users can belong to multiple cafes
- each cafe can assign different roles
- matches real-world multi-location business behaviour

### 4. Email verification and password setup flows

Reason:

- more secure than temporary passwords
- more realistic onboarding
- helps support manual account creation by staff/admins

### 5. Archived-before-delete cafe lifecycle

Reason:

- reduces accidental permanent deletion
- shows safer admin workflow design

## Suggested Testing Areas

The most important areas to test are:

- login and email verification
- password reset and setup flows
- invite create, resend, revoke, and accept flows
- cafe owner transfer protections
- archived cafe deletion rules
- customer suspension and reactivation
- slug route navigation
- role-based page access

## Conclusion

This system was designed to balance usability, realistic business features, and software engineering structure. It is more than a simple loyalty card app because it includes multi-role access control, configurable cafe behaviour, branded public pages, email workflows, moderation tools, and safe admin operations.

That combination demonstrates both technical depth and practical design thinking.
