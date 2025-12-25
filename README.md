# Application Security MVP (Express + MongoDB)

A small role-based authentication demo built for an application security module. It includes:

- Email verification at registration
- Password hashing with `bcrypt`
- JWT authentication + role-based access control (RBAC)
- Anti-bruteforce controls (failed login + lockout)
- One-Time Password (OTP) step during login

## Tech stack

- Backend: Node.js, Express
- Database: MongoDB + Mongoose
- Auth: `jsonwebtoken`, `bcrypt`
- Email: `nodemailer` (Gmail transport)
- Frontend: static HTML/CSS/JS served by Express

## Project structure

- [server.js](server.js) — Express server + MongoDB connection + static frontend
- [route/userRouter.js](route/userRouter.js) — API routes (register/login/protected/verify/otp)
- [Controller/authFunction.js](Controller/authFunction.js) — auth logic (signup/login/JWT/RBAC/OTP/email)
- [Database/member.js](Database/member.js) — Member schema
- [Database/antibruteforce.js](Database/antibruteforce.js) — failed login + lockout schema
- [frontend/](frontend/) — pages and client JS

## Setup

### 1) Install dependencies

```bash
npm install
```


### 2) Configure environment variables

Create a `.env` file in the project root with the following variables (all are required for correct operation):

```bash
# REQUIRED: Used for all email/verification links. Must be the public base URL of your deployed app (e.g. https://your-app.onrender.com)
PUBLIC_BASE_URL=http://localhost:3000

# Server
PORT=3000

# MongoDB
DB_CONNECT=mongodb+srv://<user>:<password>@<cluster>/<db>?retryWrites=true&w=majority

# JWT
APP_SECRET=replace_with_long_random_secret
VERIFICATION_SECRET=replace_with_long_random_secret

# Email (Gmail + App Password)
EMAIL_USER=your_gmail@gmail.com
EMAIL_PASS=your_gmail_app_password
```

**Note:**
- `PUBLIC_BASE_URL` is now required and used for all verification/email links. Set this to your deployed app's public URL (e.g. `https://your-app.onrender.com`).
- If not set, registration and email verification will fail.

Notes:
- For Gmail, use an **App Password** (not your normal Gmail password).
- `DB_CONNECT` should be a valid MongoDB connection string. (The server also supports `DB_connect` for backwards compatibility.)

### 3) Run

```bash
npm start
```

Open:
- `http://localhost:<PORT>/` (serves [frontend/index.html](frontend/index.html))

## Cloning the repo / using a new database

If someone downloads this repo from GitHub:

- They will NOT automatically connect to your MongoDB Atlas unless they have valid credentials and their IP is allowed in Atlas.
- They should create their own `.env` from [.env.example](.env.example) and point `DB_CONNECT` to their own MongoDB (local or Atlas).

### Will collections be created automatically?

Yes. MongoDB creates the database + collections the first time your code writes data.

In this app, collections are created when registration/login flows run (e.g., `Member.save()` or `FailedLogin.findOneAndUpdate(..., { upsert: true })`).

Expected collection names (Mongoose default pluralization):

- `members` (from model name `member` in [Database/member.js](Database/member.js))
- `failedlogins` (from model name `FailedLogin` in [Database/antibruteforce.js](Database/antibruteforce.js))

## User flows

### Registration + email verification

1. Go to `Register` and create an account.
2. Backend sends a verification email with a link:
   - `GET /verify/:token`
3. After verifying, log in.

### Login + OTP

1. Log in with name/email + password + selected role.
2. After the password is correct, the server responds with `"OTP required"` and the UI shows an OTP form and calls:
   - `POST /generate-otp`
   - `POST /verify-otp`
3. On success, you’re redirected to [frontend/dashboard.html](frontend/dashboard.html).

## API endpoints (summary)

Base URL: `http://localhost:3000`

### Public

- `GET /public` → returns `"Public Domian"`

### Register

- `POST /register-member`
- `POST /register-admin`
- `POST /register-logistic`
- `POST /register-merchant`

Body:

```json
{ "name": "alice123", "email": "alice@example.com", "password": "StrongP@ssw0rd!" }
```

### Login

- `POST /login-member`
- `POST /login-admin`
- `POST /login-logistic`
- `POST /login-merchant`

Body:

```json
{ "identifier": "alice123", "password": "StrongP@ssw0rd!" }
```

### Protected (RBAC)

Requires `Authorization: Bearer <token>`

- `GET /member-protected`
- `GET /admin-protected`
- `GET /logistic-protected`
- `GET /merchant-protected`

### OTP

- `POST /generate-otp`

Body:

```json
{ "userId": "<mongodb_object_id>" }
```

- `POST /verify-otp`

Body:

```json
{ "userId": "<mongodb_object_id>", "otp": "1234" }
```

## Security controls (OWASP mapping)

This section maps your implemented controls to common OWASP Top 10-style themes.

### Authentication & access control

- Password hashing: `bcrypt.hash(password, 12)` in [Controller/authFunction.js](Controller/authFunction.js)
- Password strength checks: minimum length, no whitespace, upper/lower/digit/special in [Controller/authFunction.js](Controller/authFunction.js)
- JWT auth middleware: `memberAuth` verifies `Authorization: Bearer <token>` in [Controller/authFunction.js](Controller/authFunction.js)
- RBAC checks: `checkRole([roles])` for protected endpoints in [Controller/authFunction.js](Controller/authFunction.js)

### Brute force protection

- Tracks failed attempts and locks accounts after thresholds using [Database/antibruteforce.js](Database/antibruteforce.js)
- Login lockout logic in [Controller/authFunction.js](Controller/authFunction.js)

### Email verification

- Registration generates a verification JWT signed with `VERIFICATION_SECRET`
- Verification endpoint updates the user record in [route/userRouter.js](route/userRouter.js)

### OTP (MFA-like step)

- OTP generation + hashing (`sha256`) + expiry stored in user record
- OTP emailed to user via Nodemailer
- OTP verification route issues a JWT upon success

## Known issues / demo notes (based on current code)

These are worth calling out in a security assignment report because they affect correctness and security behavior:

- JWT expiry is extremely short:
  - Access token uses `expiresIn: "10s"` in [Controller/authFunction.js](Controller/authFunction.js).
  - Good for demos of expiry handling, but not realistic for a normal session.

- OTP “requires” flag logic:
  - OTP is enforced after a correct password by returning `"OTP required"`.
  - The flag `requiresOTPVerification` is used as an “OTP pending” marker: set to `true` during the OTP step and reset to `false` after successful verification.

- OTP email sender env var:
  - OTP emails send from `EMAIL_USER`.

## License

School project / demo.
