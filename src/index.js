import { createRemoteJWKSet, jwtVerify } from "jose";

let jwks;

const escapeHtml = (value) =>
  String(value).replace(/[&<>"']/g, (character) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;",
  })[character]);

const textResponse = (message, status) =>
  new Response(message, {
    status,
    headers: {
      "Content-Type": "text/plain; charset=utf-8",
      "Cache-Control": "no-store",
    },
  });

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    const isIdentityPage =
      url.pathname === "/secure" || url.pathname === "/secure/";

    const flagMatch = url.pathname.match(/^\/secure\/([A-Z]{2})$/);

    if (!isIdentityPage && !flagMatch) {
      return textResponse("Not found", 404);
    }

    if (request.method !== "GET") {
      return new Response("Method not allowed", {
        status: 405,
        headers: {
          Allow: "GET",
          "Cache-Control": "no-store",
        },
      });
    }

    const token = request.headers.get("Cf-Access-Jwt-Assertion");

    if (!token) {
      return textResponse("Access token missing", 403);
    }

    if (!env.TEAM_DOMAIN || !env.POLICY_AUD) {
      return textResponse("Access configuration missing", 500);
    }

    let identity;

    try {
      jwks ??= createRemoteJWKSet(
        new URL(`${env.TEAM_DOMAIN}/cdn-cgi/access/certs`)
      );

      const { payload } = await jwtVerify(token, jwks, {
        issuer: env.TEAM_DOMAIN,
        audience: env.POLICY_AUD,
        algorithms: ["RS256"],
        requiredClaims: ["exp", "iat", "email"],
      });

      if (
        typeof payload.email !== "string" ||
        typeof payload.iat !== "number"
      ) {
        throw new Error("Required identity claims missing");
      }

      identity = payload;
    } catch {
      return textResponse("Access token invalid", 403);
    }

    // Both the identity page and flag route require a valid token.
    if (flagMatch) {
      const country = flagMatch[1];
      const key = `flags/${country.toLowerCase()}.svg`;

      try {
        const object = await env.anoj_country_flags.get(key);

        if (object === null) {
          return textResponse("Flag not found", 404);
        }

        return new Response(object.body, {
          headers: {
            "Content-Type": "image/svg+xml",
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
          },
        });
      } catch {
        return textResponse("Flag storage unavailable", 503);
      }
    }

    const email = escapeHtml(identity.email);
    const timestamp = new Date(identity.iat * 1000).toISOString();

    const rawCountry = request.cf?.country;
    const country =
      typeof rawCountry === "string" && /^[A-Z]{2}$/.test(rawCountry)
        ? rawCountry
        : null;

    const countryHtml = country
      ? `<a href="/secure/${country}">${country}</a>`
      : "unknown";

    return new Response(
      `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Cloudflare Access Demo</title>
  </head>
  <body>
    <h1>Cloudflare Access Demo</h1>
    <p>${email} authenticated at ${timestamp} (UTC) from ${countryHtml}</p>
  </body>
</html>`,
      {
        headers: {
          "Content-Type": "text/html; charset=utf-8",
          "Cache-Control": "no-store",
          "X-Content-Type-Options": "nosniff",
        },
      }
    );
  },
};
