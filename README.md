# Transpot Backend

Express API for the SinghRJ Transport frontend. Quote and support submissions are stored in MongoDB Atlas; admin routes use a signed, HTTP-only session cookie.

## Run locally

1. Run `npm ci`.
2. Copy `.env.example` to `.env` and set `MONGODB_URI`, `ADMIN_EMAIL`, `ADMIN_PASSWORD_HASH`, and `JWT_SECRET`.
3. Run `npm run dev`. The API listens on port 3000 by default.

Generate a bcrypt hash locally without putting the password in source control:

```powershell
$securePassword = Read-Host "Admin password" -AsSecureString
$env:ADMIN_PASSWORD = [System.Net.NetworkCredential]::new('', $securePassword).Password
node --input-type=module -e "import bcrypt from 'bcryptjs'; console.log(await bcrypt.hash(process.env.ADMIN_PASSWORD, 12))"
Remove-Item Env:ADMIN_PASSWORD
Remove-Variable securePassword
```

Set the printed hash as `ADMIN_PASSWORD_HASH`. Keep `.env` and all credential values private.

## Deploy to Render

Create a Render Blueprint from this repository's `render.yaml`. It creates the `traspot-backend` web service with `npm ci`, `npm start`, and `/api/health` as its health check. Set `MONGODB_URI`, `ADMIN_EMAIL`, `ADMIN_PASSWORD_HASH`, and `JWT_SECRET` as Render secrets. Use a URL-encoded Atlas database password and a random `JWT_SECRET` of at least 32 characters.

In MongoDB Atlas, allow the Render service's outbound IP ranges and grant its database user only the permissions the app needs. Avoid allowing all IP addresses unless you have deliberately accepted that risk.

The expected API URL is `https://traspot-backend.onrender.com`. The frontend repository's `vercel.json` proxies `/api/*` to this URL, keeping admin requests same-origin. If Render assigns a different URL, update that Vercel rewrite.

The Blueprint uses Render's free plan, which can spin down while idle. Upgrade the service if it needs to remain continuously warm.
