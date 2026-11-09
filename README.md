# Cloudflare Access Worker

A Cloudflare Worker that displays the authenticated user's identity and
serves country flags from a private R2 bucket.

## Access

Open https://tunnel.anoj.dev/secure and sign in through Cloudflare Access.

Access is restricted to my configured user account and users with an
@cloudflare.com email address.

The page displays:

> EMAIL authenticated at TIMESTAMP from COUNTRY

Click the country link to view its flag at `/secure/{COUNTRY}`, for example
`/secure/DE`.

## Implementation

- Cloudflare Access handles sign-in and access policies.
- The Worker validates the Access JWT signature, issuer, audience and expiry.
- `/secure` returns the identity information as HTML.
- `/secure/{COUNTRY}` returns the flag as `image/svg+xml`.
- Flag SVGs are stored in the private `anoj-country-flags` R2 bucket and
  accessed through the `anoj_country_flags` binding.
- The timestamp is derived from the Access JWT's `iat` (issued-at) claim.

## Local setup and deployment

Requires Node.js, npm and access to the target Cloudflare account.

```bash
npm ci
npx wrangler login
npx wrangler deploy
```

For deployment to another account, update the routes, Access team domain,
policy audience and R2 bucket in `wrangler.jsonc`. Configure Cloudflare
Access separately and upload the flag SVGs to the private bucket under
`flags/`, using lowercase filenames such as `flags/de.svg`.

Pushing to GitHub does not deploy the Worker. Deployment is performed
locally with Wrangler.

## Flag attribution

Flag SVGs are from [flag-icons](https://github.com/lipis/flag-icons),
licensed under the MIT License. License and source information are
included in `licenses/`.
