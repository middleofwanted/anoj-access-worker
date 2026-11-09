import { createRemoteJWKSet, jwtVerify } from "jose";

let jwks;

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    if (url.pathname !== "/secure" && url.pathname !== "/secure/") {
      return new Response("Not found", { status: 404 });
    }

    const token = request.headers.get("Cf-Access-Jwt-Assertion");

    if (!token) {
      return new Response("Access token missing", {
        status: 403,
        headers: { "Cache-Control": "no-store" },
      });
    }

    if (!env.TEAM_DOMAIN || !env.POLICY_AUD) {
      return new Response("Access configuration missing", {
        status: 500,
        headers: { "Cache-Control": "no-store" },
      });
    }

    try {
      jwks ??= createRemoteJWKSet(
        new URL(`${env.TEAM_DOMAIN}/cdn-cgi/access/certs`)
      );

      await jwtVerify(token, jwks, {
        issuer: env.TEAM_DOMAIN,
        audience: env.POLICY_AUD,
        algorithms: ["RS256"],
        requiredClaims: ["exp", "iat", "email"],
      });
    } catch {
      return new Response("Access token invalid", {
        status: 403,
        headers: { "Cache-Control": "no-store" },
      });
    }

    return new Response(
      `<!doctype html>
<html lang="de">
  <head>
    <meta charset="utf-8">
    <title>Cloudflare Access Demo</title>
  </head>
  <body>
    <h1>Cloudflare Access Demo</h1>
    <p>Das Access-Token wurde erfolgreich geprüft.</p>
  </body>
</html>`,
      {
        headers: {
          "Content-Type": "text/html; charset=utf-8",
          "Cache-Control": "no-store",
        },
      }
    );
  },
};
