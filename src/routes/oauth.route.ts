import { Router, type Request, type Response } from "express";
import { db } from "../db/db.js";
import {
  oauthClients,
  authCodes,
  accessTokens,
  refreshTokens,
  cortexSessions,
  pendingOAuthFlows,
  users,
} from "../db/schema.js";
import { eq, and } from "drizzle-orm";
import { v4 as uuidv4 } from "uuid";
import {
  signAccessToken,
  signIdToken,
  signRefreshToken,
  verifyToken,
} from "../utils/jwt.js";
import {
  verifyPKCE,
  generateSecureToken,
} from "../utils/proof_key_code_exchange.js";
import { validateClient } from "../middlewares/validateClient.js";

export const oauthRouter = Router();

oauthRouter.get("/authorize", async (req: Request, res: Response) => {
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
});

oauthRouter.post(
  "/token",
  validateClient,
  async (req: Request, res: Response) => {
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
  },
);

oauthRouter.post(
  "/revoke",
  validateClient,
  async (req: Request, res: Response) => {
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

    res.json({ ok: true });
  },
);
