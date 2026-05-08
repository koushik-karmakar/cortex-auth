import type { Request, Response } from "express";
import { db } from "../db/db.js";
import {
  accessTokens,
  authCodes,
  cortexSessions,
  oauthClients,
  pendingOAuthFlows,
  refreshTokens,
  users,
} from "../db/schema.js";
import { eq, and } from "drizzle-orm";
import { v4 as uuidv4 } from "uuid";
import {
  generateSecureToken,
  verifyPKCE,
} from "../utils/proof_key_code_exchange.js";
import {
  signAccessToken,
  signIdToken,
  signRefreshToken,
  verifyToken,
} from "../utils/jwt.js";

class OAuth_controller {
  authorize = async (req: Request, res: Response) => {
    const {
      client_id,
      redirect_uri,
      response_type,
      scope,
      state,
      code_challenge,
      code_challenge_method,
      _cortex_authed,
    } = req.query as Record<string, string>;

    if (!client_id || !redirect_uri || response_type !== "code") {
      res.status(400).json({
        error: "invalid_request",
        error_description: "Missing required parameters",
      });
      return;
    }

    const [client] = await db
      .select()
      .from(oauthClients)
      .where(eq(oauthClients.clientId, client_id))
      .limit(1);

    if (!client) {
      res.status(400).json({
        error: "invalid_client",
        error_description: "Unknown client_id",
      });
      return;
    }

    if (!client.redirectUris.includes(redirect_uri)) {
      res.status(400).json({
        error: "invalid_request",
        error_description: "Invalid redirect_uri",
      });
      return;
    }

    const requestedScopes = scope ? scope.split(" ") : ["openid"];
    const allowedScopes = requestedScopes.filter((s) =>
      client.scopes.includes(s),
    );

    const sessionId = req.cookies?.cortex_session as string | undefined;
    let loggedInUserId: string | null = null;

    if (sessionId) {
      const [session] = await db
        .select()
        .from(cortexSessions)
        .where(and(eq(cortexSessions.id, sessionId)))
        .limit(1);

      if (session && session.expiresAt > new Date()) {
        loggedInUserId = session.userId;
      }
    }

    if (!loggedInUserId) {
      const flowState = state ?? generateSecureToken(16);
      await db
        .insert(pendingOAuthFlows)
        .values({
          state: flowState,
          params: {
            client_id,
            redirect_uri,
            response_type,
            scope: scope ?? "openid",
            state: state ?? "",
            code_challenge: code_challenge ?? "",
            code_challenge_method: code_challenge_method ?? "",
          },
          expiresAt: new Date(Date.now() + 10 * 60 * 1000),
        })
        .onConflictDoUpdate({
          target: pendingOAuthFlows.state,
          set: {
            params: {
              client_id,
              redirect_uri,
              response_type,
              scope: scope ?? "openid",
              state: state ?? "",
              code_challenge: code_challenge ?? "",
              code_challenge_method: code_challenge_method ?? "",
            },
            expiresAt: new Date(Date.now() + 10 * 60 * 1000),
          },
        });

      res.redirect(`/auth/login?state=${encodeURIComponent(flowState)}`);
      return;
    }

    const [user] = await db
      .select()
      .from(users)
      .where(eq(users.id, loggedInUserId))
      .limit(1);

    if (!user) {
      res.clearCookie("cortex_session");
      res.redirect(`/auth/login?state=${encodeURIComponent(state ?? "")}`);
      return;
    }

    if (!_cortex_authed) {
      res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>Continue · Cortex</title>
  <style>
    *{box-sizing:border-box;margin:0;padding:0}
    body{font-family:system-ui,sans-serif;background:#f4f4f6;display:flex;
         align-items:center;justify-content:center;min-height:100vh}
    .card{background:#fff;border-radius:20px;padding:2.5rem 2rem;width:100%;
          max-width:400px;box-shadow:0 4px 32px rgba(0,0,0,.08);text-align:center}
    .app-icon{width:56px;height:56px;border-radius:14px;background:#7f77dd;
              display:flex;align-items:center;justify-content:center;
              margin:0 auto 1rem;font-size:24px;color:#fff;font-weight:700}
    .app-name{font-size:18px;font-weight:600;color:#1a1a1a;margin-bottom:.25rem}
    .app-url{font-size:13px;color:#888;margin-bottom:1.5rem}
    .divider{border:none;border-top:1px solid #f0f0f4;margin:1.25rem 0}
    .user-row{display:flex;align-items:center;gap:.75rem;
              background:#f8f8fb;border-radius:12px;padding:.875rem 1rem;
              margin-bottom:1.5rem;text-align:left}
    .avatar{width:40px;height:40px;border-radius:50%;background:#7f77dd;
            color:#fff;font-size:16px;font-weight:600;display:flex;
            align-items:center;justify-content:center;flex-shrink:0;overflow:hidden}
    .avatar img{width:100%;height:100%;object-fit:cover}
    .user-info{flex:1;min-width:0}
    .user-name{font-size:14px;font-weight:600;color:#1a1a1a;
               white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
    .user-email{font-size:12px;color:#888;
                white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
    .scopes{text-align:left;margin-bottom:1.5rem}
    .scopes-title{font-size:12px;color:#666;margin-bottom:.5rem;font-weight:500}
    .scope-item{display:flex;align-items:center;gap:.5rem;
                font-size:13px;color:#444;padding:.3rem 0}
    .scope-item::before{content:"✓";color:#7f77dd;font-weight:700;flex-shrink:0}
    .btn{display:block;width:100%;padding:.8rem 1rem;border-radius:10px;
         border:none;font-size:15px;font-weight:600;cursor:pointer;
         transition:opacity .15s;text-decoration:none;text-align:center}
    .btn:hover{opacity:.88}
    .btn-primary{background:#7f77dd;color:#fff;margin-bottom:.75rem}
    .btn-secondary{background:#f0f0f4;color:#555;font-size:13px;font-weight:500}
    .powered{margin-top:1.5rem;font-size:11px;color:#bbb}
    .powered strong{color:#7f77dd}
  </style>
</head>
<body>
<div class="card">
  
  <div class="app-name">${client.name}</div>
  <hr class="divider"/>

  <div class="user-row">
    <div class="avatar">
      ${
        user.picture
          ? `<img src="${user.picture}" alt="${user.name}"/>`
          : user.name.charAt(0).toUpperCase()
      }
    </div>
    <div class="user-info">
      <div class="user-name">${user.name}</div>
      <div class="user-email">${user.email}</div>
    </div>
  </div>

  <div class="scopes">
    <p class="scopes-title">This app will be able to:</p>
    ${
      allowedScopes.includes("profile")
        ? `<div class="scope-item">See your name and profile picture</div>`
        : ""
    }
    ${
      allowedScopes.includes("email")
        ? `<div class="scope-item">See your email address</div>`
        : ""
    }
    ${
      allowedScopes.includes("openid")
        ? `<div class="scope-item">Confirm your identity</div>`
        : ""
    }
  </div>

  <form method="GET" action="/oauth/authorize">
    <input type="hidden" name="client_id"            value="${client_id}"/>
    <input type="hidden" name="redirect_uri"          value="${redirect_uri}"/>
    <input type="hidden" name="response_type"         value="code"/>
    <input type="hidden" name="scope"                 value="${scope ?? "openid profile email"}"/>
    <input type="hidden" name="state"                 value="${state ?? ""}"/>
    <input type="hidden" name="code_challenge"        value="${code_challenge ?? ""}"/>
    <input type="hidden" name="code_challenge_method" value="${code_challenge_method ?? ""}"/>
    <input type="hidden" name="_cortex_authed"        value="1"/>
    <button type="submit" class="btn btn-primary">
      Continue as ${user.name.split(" ")[0]} →
    </button>
  </form>

  <a class="btn btn-secondary"
     href="/auth/logout?post_logout_redirect_uri=${encodeURIComponent(
       `/oauth/authorize?client_id=${client_id}&redirect_uri=${encodeURIComponent(redirect_uri)}&response_type=code&scope=${encodeURIComponent(scope ?? "openid profile email")}&state=${encodeURIComponent(state ?? "")}`,
     )}">
    Use a different account
  </a>

  <p class="powered">Powered by <strong>Cortex</strong></p>
</div>
</body>
</html>`);
      return;
    }

    const code = generateSecureToken(32);
    await db.insert(authCodes).values({
      id: code,
      clientId: client_id,
      userId: user.id,
      redirectUri: redirect_uri,
      scopes: allowedScopes,
      codeChallenge: code_challenge ?? null,
      codeChallengeMethod: code_challenge_method ?? null,
      expiresAt: new Date(Date.now() + 60 * 1000),
    });

    const callbackUrl = new URL(redirect_uri);
    callbackUrl.searchParams.set("code", code);
    if (state) callbackUrl.searchParams.set("state", state);

    res.redirect(callbackUrl.toString());
  };

  authToken = async (req: Request, res: Response) => {
    const { grant_type, code, redirect_uri, refresh_token, code_verifier } =
      req.body as Record<string, string>;

    const client = req.oauthClient!;

    if (grant_type === "authorization_code") {
      if (!code || !redirect_uri) {
        res.status(400).json({
          error: "invalid_request",
          error_description: "Missing code or redirect_uri",
        });
        return;
      }

      const [authCode] = await db
        .select()
        .from(authCodes)
        .where(eq(authCodes.id, code))
        .limit(1);

      if (!authCode) {
        res
          .status(400)
          .json({ error: "invalid_grant", error_description: "Unknown code" });
        return;
      }

      if (authCode.used) {
        await db
          .update(accessTokens)
          .set({ revoked: true })
          .where(
            and(
              eq(accessTokens.clientId, client.clientId),
              eq(accessTokens.userId, authCode.userId),
            ),
          );
        res.status(400).json({
          error: "invalid_grant",
          error_description: "Code already used",
        });
        return;
      }

      if (authCode.expiresAt < new Date()) {
        res
          .status(400)
          .json({ error: "invalid_grant", error_description: "Code expired" });
        return;
      }

      if (authCode.clientId !== client.clientId) {
        res.status(400).json({
          error: "invalid_grant",
          error_description: "Code was not issued to this client",
        });
        return;
      }

      if (authCode.redirectUri !== redirect_uri) {
        res.status(400).json({
          error: "invalid_grant",
          error_description: "redirect_uri mismatch",
        });
        return;
      }

      if (authCode.codeChallenge) {
        if (!code_verifier) {
          res.status(400).json({
            error: "invalid_grant",
            error_description: "Missing code_verifier",
          });
          return;
        }
        const valid = verifyPKCE(
          code_verifier,
          authCode.codeChallenge,
          authCode.codeChallengeMethod ?? "plain",
        );
        if (!valid) {
          res.status(400).json({
            error: "invalid_grant",
            error_description: "PKCE verification failed",
          });
          return;
        }
      }

      await db
        .update(authCodes)
        .set({ used: true })
        .where(eq(authCodes.id, code));

      const [user] = await db
        .select()
        .from(users)
        .where(eq(users.id, authCode.userId))
        .limit(1);

      if (!user) {
        res.status(400).json({
          error: "invalid_grant",
          error_description: "User not found",
        });
        return;
      }

      const jti = uuidv4();
      const now = new Date();
      const accessTokenExpiry = new Date(now.getTime() + 60 * 60 * 1000);

      const accessTokenValue = await signAccessToken({
        sub: user.id,
        jti,
        email: user.email,
        name: user.name,
        ...(user.picture && { picture: user.picture }),
        client_id: client.clientId,
        scope: authCode.scopes.join(" "),
      });

      const idTokenValue = await signIdToken({
        sub: user.id,
        aud: client.clientId,
        email: user.email,
        name: user.name,
        ...(user.picture && { picture: user.picture }),
      });

      const refreshTokenId = uuidv4();
      const refreshTokenValue = await signRefreshToken({
        sub: user.id,
        jti: refreshTokenId,
        client_id: client.clientId,
      });

      await db.insert(accessTokens).values({
        id: jti,
        clientId: client.clientId,
        userId: user.id,
        scopes: authCode.scopes,
        expiresAt: accessTokenExpiry,
      });

      await db.insert(refreshTokens).values({
        id: refreshTokenId,
        accessTokenId: jti,
        clientId: client.clientId,
        userId: user.id,
        scopes: authCode.scopes,
        expiresAt: new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000),
      });

      res.json({
        access_token: accessTokenValue,
        id_token: idTokenValue,
        refresh_token: refreshTokenValue,
        token_type: "Bearer",
        expires_in: 3600,
        scope: authCode.scopes.join(" "),
      });
      return;
    }

    if (grant_type === "refresh_token") {
      if (!refresh_token) {
        res.status(400).json({
          error: "invalid_request",
          error_description: "Missing refresh_token",
        });
        return;
      }

      let payload;
      try {
        payload = await verifyToken(refresh_token);
      } catch {
        res.status(400).json({
          error: "invalid_grant",
          error_description: "Invalid refresh token",
        });
        return;
      }

      const [storedRefresh] = await db
        .select()
        .from(refreshTokens)
        .where(eq(refreshTokens.id, payload.jti!))
        .limit(1);

      if (
        !storedRefresh ||
        storedRefresh.revoked ||
        storedRefresh.expiresAt < new Date()
      ) {
        res.status(400).json({
          error: "invalid_grant",
          error_description: "Refresh token expired or revoked",
        });
        return;
      }

      if (storedRefresh.clientId !== client.clientId) {
        res.status(400).json({
          error: "invalid_grant",
          error_description: "Token not issued to this client",
        });
        return;
      }

      const [user] = await db
        .select()
        .from(users)
        .where(eq(users.id, storedRefresh.userId))
        .limit(1);

      if (!user) {
        res.status(400).json({ error: "invalid_grant" });
        return;
      }

      await db
        .update(refreshTokens)
        .set({ revoked: true })
        .where(eq(refreshTokens.id, storedRefresh.id));

      const jti = uuidv4();
      const accessTokenExpiry = new Date(Date.now() + 60 * 60 * 1000);

      const newAccessToken = await signAccessToken({
        sub: user.id,
        jti,
        email: user.email,
        name: user.name,
        ...(user.picture && { picture: user.picture }),
        client_id: client.clientId,
        scope: storedRefresh.scopes.join(" "),
      });

      const newRefreshTokenId = uuidv4();
      const newRefreshToken = await signRefreshToken({
        sub: user.id,
        jti: newRefreshTokenId,
        client_id: client.clientId,
      });

      await db.insert(accessTokens).values({
        id: jti,
        clientId: client.clientId,
        userId: user.id,
        scopes: storedRefresh.scopes,
        expiresAt: accessTokenExpiry,
      });

      await db.insert(refreshTokens).values({
        id: newRefreshTokenId,
        accessTokenId: jti,
        clientId: client.clientId,
        userId: user.id,
        scopes: storedRefresh.scopes,
        expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
      });

      res.json({
        access_token: newAccessToken,
        refresh_token: newRefreshToken,
        token_type: "Bearer",
        expires_in: 3600,
        scope: storedRefresh.scopes.join(" "),
      });
      return;
    }

    res.status(400).json({ error: "unsupported_grant_type" });
  };

  authRevoke = async (req: Request, res: Response) => {
    const { token } = req.body as { token?: string };
    if (!token) {
      res.status(400).json({ error: "invalid_request" });
      return;
    }

    try {
      const payload = await verifyToken(token);
      if (payload.jti) {
        await db
          .update(accessTokens)
          .set({ revoked: true })
          .where(eq(accessTokens.id, payload.jti));
        await db
          .update(refreshTokens)
          .set({ revoked: true })
          .where(eq(refreshTokens.id, payload.jti));
      }
    } catch {
      // return with 200
    }

    res.send(200).json({ ok: true });
  };
}

export const oauthController = new OAuth_controller();
