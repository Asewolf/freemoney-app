# Free Money — Cloud Deploy

Slim, deployable Flask app for [myfreemoney.app](https://myfreemoney.app).

Settlements / scholarships / cashback claims aggregated from 50+ public sources.
Pro subscription via Stripe ($4.99/mo or $54/yr, 7-day free trial).

## Local dev

```bash
pip install -r requirements.txt
cp .env.example .env  # fill in Stripe keys etc
python app.py
# → http://localhost:8080/freemoney
```

## Deploy to Railway

1. Push this directory to GitHub
2. railway.app → New Project → Deploy from GitHub repo
3. Add a **Volume** and mount it at `/data` (so settlements.db survives deploys)
4. Set the env vars from `.env.example` in Railway dashboard
5. Custom domain: point `myfreemoney.app` (CNAME) at the Railway-provided URL

## Stripe webhook

After deploy, register a webhook in Stripe Dashboard:
- URL: `https://myfreemoney.app/api/stripe/webhook`
- Events:
  - `checkout.session.completed`
  - `customer.subscription.deleted`
  - `customer.subscription.updated`
  - `customer.subscription.paused`
  - `customer.subscription.resumed`
  - `invoice.payment_failed`

Copy the signing secret into `STRIPE_WEBHOOK_SECRET`.

## Database

SQLite at `$DB_PATH` (default `/data/settlements.db`). To seed it on a fresh
deploy, upload your existing `settlements.db` to the Volume.

Workers in `workers/` populate it on a cron schedule.
