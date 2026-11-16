# Sentinel In-Browser DLP — Backend & Security Admin Console

[![Laravel](https://img.shields.io/badge/Laravel-13.x-FF2D20?style=flat&logo=laravel&logoColor=white)](https://laravel.com)
[![Filament](https://img.shields.io/badge/Filament-5.x-F59E0B?style=flat&logo=filament&logoColor=white)](https://filamentphp.com)
[![PHP](https://img.shields.io/badge/PHP-8.3%2B-777BB4?style=flat&logo=php&logoColor=white)](https://www.php.net)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Sentinel In-Browser DLP is an enterprise-grade Data Loss Prevention solution designed to monitor, inspect, and enforce data security policies on AI prompt submissions (Google Gemini, OpenAI ChatGPT, Anthropic Claude).

This repository contains the **Central Backend API and Filament Admin Console**. It manages DLP detection rules, provides real-time policy sync for browser extensions, and acts as the centralized audit log for all intercepted security events.

---

## Architecture Overview

- **Backend / Management Console (`backend` branch)**:
  - Built with **Laravel 13** and **Filament 5**.
  - Serves REST APIs for real-time policy delivery and incident reporting.
  - Features an administrative Security Operations Center (SOC) with live widgets, slide-over incident inspectors, and audit logs.
  - Automatically clears caches and bumps version hashes upon policy changes via `DlpPolicyObserver`.
- **Browser Extension (`frontend` branch)**:
  - Manifest V3 Chrome Extension located in the `frontend` branch.
  - Captures DOM submissions (`Enter` key, Send buttons) and hooks `fetch` / `XMLHttpRequest`.
  - Blocks or redacts sensitive prompt data in real time and reports incidents to this backend.

---

## Features

- **Dynamic Policy Enforcement**:
  - **Detection Types**: Regular Expressions (Regex), Keyword lists, and Shannon Entropy (for detecting random keys/tokens).
  - **Enforcement Actions**: Hard Block (`block`), Warning with User Override (`warn`), Automated Redaction (`redact`), and Silent Audit (`log`).
  - **Domain Scoping**: Target specific AI platforms (e.g., `gemini.google.com`, `chatgpt.com`, `claude.ai`) or enforce globally across all AI tools.
- **Comprehensive Incident Telemetry ("Who Entered What, Everything")**:
  - **Who**: Unique client identifier, client IP address, and browser User-Agent.
  - **Where**: AI platform / domain target.
  - **What**: The exact full prompt typed by the user, alongside the masked sensitive sample.
  - **Action Taken**: Status of enforcement (Blocked, Warning Overridden, Redacted, Logged).
  - **When**: Precise timestamp with human-readable relative time.
- **Real-Time SOC Dashboard**:
  - Live KPI statistics: Total Security Events, Hard Blocked Prompts, Active Policies, Unique Monitored Users.
  - Recent incidents feed with instant slide-over detailed view.
- **High-Performance Caching & Observer**:
  - Active policies are cached in memory for sub-millisecond response times.
  - `DlpPolicyObserver` automatically busts server cache and updates the policy version hash immediately on create, update, or delete.

---

## Prerequisites

Ensure your development environment meets the following requirements:

- **PHP**: `^8.3` (with `pdo`, `mbstring`, `tokenizer`, `xml`, `ctype`, `json`, `curl` extensions)
- **Composer**: `^2.6`
- **Database**: MySQL `^8.0` or SQLite `^3.35`
- **Node.js & NPM**: Node `^18.0` & NPM `^9.0` (optional, for asset rebuilding)

---

## Local Setup & Installation

### 1. Clone the Repository

Clone the `backend` branch of the repository:

```bash
git clone -b backend https://github.com/MacTavish27/dlp_extension.git
cd dlp_extension
```

### 2. Install PHP & Node Dependencies

```bash
composer install
npm install
```

### 3. Environment Configuration

Copy the example environment file:

```bash
cp .env.example .env
```

Generate the application encryption key:

```bash
php artisan key:generate
```

Configure your database in `.env`:

#### Option A: Using SQLite (Quickest)
```ini
DB_CONNECTION=sqlite
```
Create the SQLite database file if it does not exist:
```bash
touch database/database.sqlite
```

#### Option B: Using MySQL
```ini
DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE=dlp_extension_db
DB_USERNAME=your_mysql_username
DB_PASSWORD=your_mysql_password
```

### 4. Run Database Migrations

Execute the migrations to create the policies and incident logging tables:

```bash
php artisan migrate
```

### 5. Create an Administrator Account

Create a Filament administrator user to access the monitoring dashboard:

```bash
php artisan make:filament-user
```
Follow the prompt to enter your Name, Email, and Password (e.g., `admin@example.com`).

### 6. Start the Local Server

Start the Laravel local development server:

```bash
php artisan serve
```

The application is now running at **`http://127.0.0.1:8000`**.

---

## Accessing the Admin Console

Open your browser and navigate to:

```text
http://127.0.0.1:8000/admin
```

Log in using the administrator credentials created in Step 5.

### Console Sections:
- **Dashboard (`/admin`)**: Real-time overview of security KPIs and the latest monitored AI security events.
- **Incident Monitoring (`/admin/dlp-incidents`)**: Complete audit log of every detected violation. Click **View** on any row to open the slide-over inspector showing:
  - User ID, Client IP, and Browser User-Agent.
  - The **complete prompt text** entered by the user.
  - The masked sensitive token.
- **Detection Policies (`/admin/dlp-policies`)**: Create, edit, and toggle DLP policies. Changes take effect across connected browser extensions in near real time.

---

## REST API Reference

The backend provides public API endpoints consumed by the Sentinel DLP Chrome Extension.

### 1. Get Active Policies
- **URL**: `GET /api/v1/dlp/policies`
- **Description**: Returns all currently active DLP policies and an MD5 version hash for cache validation.
- **Sample Response**:
  ```json
  {
    "version": "ae1b4dd3648f475a6c30c9befd4a1cfa",
    "policies": [
      {
        "id": 1,
        "name": "AWS Access Key Leak",
        "detection_type": "regex",
        "pattern": "AKIA[0-9A-Z]{16}",
        "action": "block",
        "severity": "critical",
        "target_domains": ["gemini.google.com", "chatgpt.com"]
      }
    ]
  }
  ```

### 2. Log DLP Incident
- **URL**: `POST /api/v1/dlp/incidents`
- **Headers**: `Content-Type: application/json`, `Accept: application/json`
- **Body Parameters**:
  - `dlp_policy_id` *(int, required)*: ID of the violated policy.
  - `user_identifier` *(string, nullable)*: Client or user ID.
  - `domain` *(string, required)*: Domain where violation occurred (e.g. `gemini.google.com`).
  - `action_taken` *(string, required)*: `block`, `warn_blocked`, `warn_bypassed`, `redact`, or `log`.
  - `masked_sample` *(string, nullable)*: Masked sensitive sample (e.g. `AK****************LE`).
  - `prompt_content` *(string, nullable)*: The prompt text entered by the user.
- **Sample Request**:
  ```bash
  curl -X POST http://127.0.0.1:8000/api/v1/dlp/incidents \
    -H "Content-Type: application/json" \
    -H "Accept: application/json" \
    -d '{
      "dlp_policy_id": 1,
      "user_identifier": "user_dev_01",
      "domain": "gemini.google.com",
      "action_taken": "block",
      "masked_sample": "AK************LE",
      "prompt_content": "Please verify my AWS key AKIAIOSFODNN7EXAMPLE"
    }'
  ```
- **Response**: `201 Created`
  ```json
  {
    "status": "recorded",
    "incident_id": 1
  }
  ```

---

## Connecting the Chrome Extension

To run the complete end-to-end DLP system:

1. Clone or checkout the `frontend` branch in a separate folder:
   ```bash
   git clone -b frontend https://github.com/MacTavish27/dlp_extension.git dlp_extension_frontend
   ```
2. Open Google Chrome and go to `chrome://extensions/`.
3. Toggle on **Developer mode** in the upper right corner.
4. Click **Load unpacked** and select the `dlp_extension_frontend` folder.
5. The extension connects to `http://127.0.0.1:8000/api/v1/dlp` by default.
6. Open **Google Gemini** (`gemini.google.com`) or **ChatGPT** (`chatgpt.com`).
7. Enter a test pattern (such as `AKIAIOSFODNN7EXAMPLE`) and hit `Enter` to see the prompt blocked in the browser and recorded in your Filament Admin Console.

---

## Testing & Quality Assurance

Run the automated test suite:

```bash
php artisan test
```

Clear all cached components and configurations:

```bash
php artisan optimize:clear
```

---

## License

This project is open-sourced software licensed under the [MIT License](LICENSE).
