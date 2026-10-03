# KaziUganda full-stack starter

## Run
1. Install Node.js 20+.
2. In this folder run: `npm install`
3. Run: `npm start`
4. Open `http://localhost:3000/login.html`

## Included
- User registration/login
- SQLite database
- User wallet balance
- Jobs listing
- Withdrawal request records
- Session authentication
- Admin-only job creation API

## Before production
- Change SESSION_SECRET.
- Use HTTPS.
- Add rate limiting, CSRF protection, validation and audit logging.
- Connect an approved Uganda payment provider on the server side.
- Do not put payment/API secrets in browser JavaScript.
- Add proper admin account provisioning.
- Replace demo balances with verified transaction records.
