import type { Request, Response } from "express";
import { OAuth2Client } from "google-auth-library";
import { env } from "../env.js";
import { db } from "../db/db.js";
import {
  adminSessions,
  cortexSessions,
  pendingOAuthFlows,
  users,
} from "../db/schema.js";
import { eq } from "drizzle-orm";
import { v4 as uuidv4 } from "uuid";
class Auth_controller {
  login = (req: Request, res: Response) => {
    const { state } = req.query as { state?: string };
    res.status(200).send(`<!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Login · Cortex</title>
      <style>
        *{box-sizing:border-box;margin:0;padding:0}
        body{font-family:system-ui,sans-serif;background:#f4f4f6;display:flex;
             align-items:center;justify-content:center;min-height:100vh}
        .card{background:#fff;border-radius:16px;padding:2.5rem 2rem;width:100%;
              max-width:380px;box-shadow:0 4px 24px rgba(0,0,0,.07);text-align:center}
        .logo{font-size:28px;font-weight:700;color:#7f77dd;margin-bottom:.5rem}
        .subtitle{color:#666;font-size:14px;margin-bottom:2rem}
        .google-btn{display:flex;align-items:center;justify-content:center;gap:10px;
          width:100%;padding:.75rem 1rem;border:1.5px solid #e0e0e4;border-radius:10px;
          background:#fff;font-size:15px;font-weight:500;color:#1a1a1a;
          cursor:pointer;text-decoration:none;transition:background .12s}
        .google-btn:hover{background:#f8f8fb}
      </style>
    </head>
    <body>
      <div class="card">
        <div class="logo">Cortex</div>
        <p class="subtitle">Sign in to continue</p>
        <a class="google-btn"
           href="/auth/google?state=${encodeURIComponent(state ?? "")}">
          <svg width="18" height="18" viewBox="0 0 48 48">
            <path fill="#4285F4" d="M44.5 20H24v8.5h11.8C34.1 33.1 29.6 36 24 36c-6.6 0-12-5.4-12-12s5.4-12 12-12c3 0 5.7 1.1 7.8 2.9l6.3-6.3C34.5 5.6 29.5 3.5 24 3.5 12.7 3.5 3.5 12.7 3.5 24S12.7 44.5 24 44.5c11 0 20.5-8 20.5-20 0-1.3-.1-2.7-.4-4Z"/>
            <path fill="#34A853" d="M6.3 14.7l7 5.1C15 16.1 19.2 13 24 13c3 0 5.7 1.1 7.8 2.9l6.3-6.3C34.5 5.6 29.5 3.5 24 3.5c-7.7 0-14.4 4.4-17.7 11.2Z"/>
            <path fill="#FBBC05" d="M24 44.5c5.4 0 10.3-1.9 14-5.1l-6.5-5.3C29.6 35.6 27 36.5 24 36.5c-5.6 0-10.2-3-11.8-7.5l-7 5.4C8 39.9 15.5 44.5 24 44.5Z"/>
            <path fill="#EA4335" d="M44.5 20H24v8.5h11.8c-.8 2.3-2.4 4.2-4.4 5.5l6.5 5.3c3.8-3.5 6.1-8.7 6.1-15.3 0-1.3-.1-2.7-.4-4Z"/>
          </svg>
          Continue with Google
        </a>
      </div>
    </body>
    </html>`);
  };
  #googleClient = new OAuth2Client(
    env.GOOGLE_CLIENT_ID,
    env.GOOGLE_CLIENT_SECRET,
    env.GOOGLE_CALLBACK_URL,
  );

  #adminGoogleClient = new OAuth2Client(
    env.GOOGLE_CLIENT_ID,
    env.GOOGLE_CLIENT_SECRET,
    `${env.APP_URL}/auth/admin/google/callback`,
  );

  generateAuthUrl = (req: Request, res: Response) => {
    const { state } = req.query as { state?: string };
    const url = this.#googleClient.generateAuthUrl({
      access_type: "offline",
      scope: ["openid", "profile", "email"],
      state: state ?? "",
      prompt: "select_account",
    });
    res.redirect(url);
  };

  googleCallBack = async (req: Request, res: Response) => {
    const { code, state } = req.query as { code?: string; state?: string };
    if (!code) {
      res.status(400).send("Missing code from Google");
      return;
    }

    try {
      const { tokens } = await this.#googleClient.getToken(code);
      this.#googleClient.setCredentials(tokens);

      const ticket = await this.#googleClient.verifyIdToken({
        idToken: tokens.id_token!,
        audience: env.GOOGLE_CLIENT_ID,
      });
      const payload = ticket.getPayload();
      if (!payload?.email) {
        res.status(400).send("Invalid Google token");
        return;
      }

      const existing = await db
        .select()
        .from(users)
        .where(eq(users.email, payload.email))
        .limit(1);

      let userId: string;
      if (existing.length > 0) {
        userId = existing[0]!.id;
        await db
          .update(users)
          .set({
            lastLoginAt: new Date(),
            name: payload.name ?? existing[0]!.name,
            picture: payload.picture ?? existing[0]!.picture,
            googleId: payload.sub,
          })
          .where(eq(users.id, userId));
      } else {
        userId = uuidv4();
        await db.insert(users).values({
          id: userId,
          email: payload.email,
          name: payload.name ?? payload.email,
          picture: payload.picture ?? null,
          googleId: payload.sub,
        });
      }

      const sessionId = uuidv4();
      const sessionExpiry = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);
      await db.insert(cortexSessions).values({
        id: sessionId,
        userId,
        expiresAt: sessionExpiry,
      });

      res.cookie("cortex_session", sessionId, {
        httpOnly: true,
        secure: env.NODE_ENV === "production",
        sameSite: "lax",
        expires: sessionExpiry,
        path: "/",
      });

      if (state) {
        const [flow] = await db
          .select()
          .from(pendingOAuthFlows)
          .where(eq(pendingOAuthFlows.state, state))
          .limit(1);

        if (flow && flow.expiresAt > new Date()) {
          await db
            .delete(pendingOAuthFlows)
            .where(eq(pendingOAuthFlows.state, state));
          const params = flow.params as Record<string, string>;
          const qs = new URLSearchParams({ ...params, _cortex_authed: "1" });
          res.redirect(`/oauth/authorize?${qs.toString()}`);
          return;
        }
      }

      res.status(200).send(`<!DOCTYPE html>
  <html><head><title>Cortex</title>
  <style>body{font-family:system-ui,sans-serif;display:flex;align-items:center;
  justify-content:center;min-height:100vh;background:#f4f4f6}
  .card{background:#fff;border-radius:16px;padding:2rem;text-align:center;
  box-shadow:0 4px 24px rgba(0,0,0,.07)}h2{color:#7f77dd}
  </style></head><body>
  <div class="card">
    <h2>Welcome, ${payload.name ?? payload.email}!</h2>
    <p style="margin-top:1rem;color:#666">You are logged in to Cortex.</p>
  </div>
  </body></html>`);
    } catch (err) {
      console.error("Google callback error:", err);
      res.status(500).send("Authentication failed");
    }
  };

  clearCookiesRedirect = async (req: Request, res: Response) => {
    const sessionId = req.cookies?.cortex_session as string | undefined;
    if (sessionId) {
      await db
        .delete(cortexSessions)
        .where(eq(cortexSessions.id, sessionId))
        .catch(() => {});
    }
    res.clearCookie("cortex_session");
    const redirectTo =
      (req.query.post_logout_redirect_uri as string) || "/auth/login";
    res.status(302).redirect(redirectTo);
  };

  clearCookies = async (req: Request, res: Response) => {
    const sessionId = req.cookies?.cortex_session as string | undefined;
    if (sessionId) {
      await db
        .delete(cortexSessions)
        .where(eq(cortexSessions.id, sessionId))
        .catch(() => {});
    }
    res.clearCookie("cortex_session");
    res.json({ ok: true });
  };

  adminLogin = (_req: Request, res: Response) => {
    res.status(200).send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Admin Login · Cortex</title>
  <style>
    *{box-sizing:border-box;margin:0;padding:0}
    body{font-family:system-ui,sans-serif;background:#1a1a2e;display:flex;
         align-items:center;justify-content:center;min-height:100vh}
    .card{background:#fff;border-radius:16px;padding:2.5rem 2rem;width:100%;
          max-width:380px;box-shadow:0 4px 40px rgba(0,0,0,.3);text-align:center}
    .logo{font-size:24px;font-weight:700;color:#7f77dd;margin-bottom:.25rem}
    .badge{display:inline-block;background:#ede9fe;color:#7f77dd;font-size:11px;
           font-weight:600;padding:2px 10px;border-radius:20px;margin-bottom:1.5rem}
    .subtitle{color:#666;font-size:14px;margin-bottom:2rem}
    .google-btn{display:flex;align-items:center;justify-content:center;gap:10px;
      width:100%;padding:.75rem 1rem;border:1.5px solid #e0e0e4;border-radius:10px;
      background:#fff;font-size:15px;font-weight:500;color:#1a1a1a;
      cursor:pointer;text-decoration:none;transition:background .12s}
    .google-btn:hover{background:#f8f8fb}
    .note{margin-top:1.5rem;font-size:12px;color:#999}
  </style>
</head>
<body>
  <div class="card">
    <div class="logo">Cortex</div>
    <div class="badge">Admin Portal</div>
    <p class="subtitle">Sign in with an authorized Google account</p>
    <a class="google-btn" href="/auth/admin/google">
      <svg width="18" height="18" viewBox="0 0 48 48">
        <path fill="#4285F4" d="M44.5 20H24v8.5h11.8C34.1 33.1 29.6 36 24 36c-6.6 0-12-5.4-12-12s5.4-12 12-12c3 0 5.7 1.1 7.8 2.9l6.3-6.3C34.5 5.6 29.5 3.5 24 3.5 12.7 3.5 3.5 12.7 3.5 24S12.7 44.5 24 44.5c11 0 20.5-8 20.5-20 0-1.3-.1-2.7-.4-4Z"/>
        <path fill="#34A853" d="M6.3 14.7l7 5.1C15 16.1 19.2 13 24 13c3 0 5.7 1.1 7.8 2.9l6.3-6.3C34.5 5.6 29.5 3.5 24 3.5c-7.7 0-14.4 4.4-17.7 11.2Z"/>
        <path fill="#FBBC05" d="M24 44.5c5.4 0 10.3-1.9 14-5.1l-6.5-5.3C29.6 35.6 27 36.5 24 36.5c-5.6 0-10.2-3-11.8-7.5l-7 5.4C8 39.9 15.5 44.5 24 44.5Z"/>
        <path fill="#EA4335" d="M44.5 20H24v8.5h11.8c-.8 2.3-2.4 4.2-4.4 5.5l6.5 5.3c3.8-3.5 6.1-8.7 6.1-15.3 0-1.3-.1-2.7-.4-4Z"/>
      </svg>
      Continue with Google
    </a>
    <p class="note">Only authorized email addresses can access this portal.</p>
  </div>
</body>
</html>`);
  };

  adminGoogleClient = (_req: Request, res: Response) => {
    const url = this.#adminGoogleClient.generateAuthUrl({
      access_type: "offline",
      scope: ["openid", "profile", "email"],
      prompt: "select_account",
    });
    res.redirect(url);
  };

  admin_session = async (req: Request, res: Response) => {
    const { code } = req.query as { code?: string };
    if (!code) {
      res.status(400).send("Missing code");
      return;
    }

    try {
      const { tokens } = await this.#adminGoogleClient.getToken(code);
      this.#adminGoogleClient.setCredentials(tokens);

      const ticket = await this.#adminGoogleClient.verifyIdToken({
        idToken: tokens.id_token!,
        audience: env.GOOGLE_CLIENT_ID,
      });
      const payload = ticket.getPayload();
      if (!payload?.email) {
        res.status(400).send("Invalid token");
        return;
      }

      if (!env.ADMIN_EMAILS.includes(payload.email.toLowerCase())) {
        res.status(403).send(`<!DOCTYPE html>
<html><head><title>Access Denied</title>
<style>body{font-family:system-ui,sans-serif;background:#f4f4f6;display:flex;
align-items:center;justify-content:center;min-height:100vh}
.card{background:#fff;padding:2rem;border-radius:16px;text-align:center;
max-width:400px;box-shadow:0 4px 24px rgba(0,0,0,.07)}
h2{color:#dc2626;margin-bottom:.75rem}p{color:#666;font-size:14px;margin-bottom:1rem}
a{color:#7f77dd;text-decoration:none;font-weight:500}
</style></head><body>
<div class="card">
  <h2>Access Denied</h2>
  <p><strong>${payload.email}</strong> is not authorized to access the admin portal.</p>
  <a href="/auth/admin/login">← Try another account</a>
</div>
</body></html>`);
        return;
      }

      const sessionId = uuidv4();
      const expiry = new Date(Date.now() + 24 * 60 * 60 * 1000);
      await db.insert(adminSessions).values({
        id: sessionId,
        email: payload.email,
        name: payload.name ?? payload.email,
        picture: payload.picture ?? null,
        expiresAt: expiry,
      });

      res.cookie("cortex_admin_session", sessionId, {
        httpOnly: true,
        secure: env.NODE_ENV === "production",
        sameSite: "lax",
        expires: expiry,
        path: "/",
      });

      res.redirect("/admin");
    } catch (err) {
      console.error("Admin Google callback error:", err);
      res.status(500).send("Authentication failed");
    }
  };

  adminLogout = async (req: Request, res: Response) => {
    const sessionId = req.cookies?.cortex_admin_session as string | undefined;
    if (sessionId) {
      await db
        .delete(adminSessions)
        .where(eq(adminSessions.id, sessionId))
        .catch(() => {});
    }
    res.clearCookie("cortex_admin_session");
    res.redirect("/auth/admin/login");
  };
}
export const authController = new Auth_controller();
