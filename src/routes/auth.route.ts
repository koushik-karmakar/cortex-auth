import { Router, type Request, type Response } from "express";
import { OAuth2Client } from "google-auth-library";
import { db } from "../db/db.js";
import { users, cortexSessions, pendingOAuthFlows } from "../db/schema.js";
import { eq } from "drizzle-orm";
import { v4 as uuidv4 } from "uuid";
import { env } from "../env.js";

export const authRouter = Router();

const googleClient = new OAuth2Client(
  env.GOOGLE_CLIENT_ID,
  env.GOOGLE_CLIENT_SECRET,
  env.GOOGLE_CALLBACK_URL,
);

authRouter.get("/login", (req: Request, res: Response) => {
  const { state } = req.query as { state?: string };

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Login to Cortex</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: system-ui, sans-serif; background: #f4f4f6; display: flex; align-items: center; justify-content: center; min-height: 100vh; }
    .card { background: white; border-radius: 16px; padding: 2.5rem 2rem; width: 100%; max-width: 380px; box-shadow: 0 4px 24px rgba(0,0,0,0.07); text-align: center; }
    .logo { font-size: 28px; font-weight: 700; color: #7f77dd; margin-bottom: 0.5rem; }
    .subtitle { color: #666; font-size: 14px; margin-bottom: 2rem; }
    .google-btn { display: flex; align-items: center; justify-content: center; gap: 10px; width: 100%; padding: 0.75rem 1rem; border: 1.5px solid #e0e0e4; border-radius: 10px; background: white; font-size: 15px; font-weight: 500; color: #1a1a1a; cursor: pointer; text-decoration: none; transition: background 0.12s; }
    .google-btn:hover { background: #f8f8fb; }
    .google-btn svg { flex-shrink: 0; }
  </style>
</head>
<body>
  <div class="card">
    <div class="logo">Cortex</div>
    <p class="subtitle">Sign in to continue</p>
    <a class="google-btn" href="/auth/google?state=${encodeURIComponent(state ?? "")}">
      <svg width="18" height="18" viewBox="0 0 48 48"><path fill="#4285F4" d="M44.5 20H24v8.5h11.8C34.1 33.1 29.6 36 24 36c-6.6 0-12-5.4-12-12s5.4-12 12-12c3 0 5.7 1.1 7.8 2.9l6.3-6.3C34.5 5.6 29.5 3.5 24 3.5 12.7 3.5 3.5 12.7 3.5 24S12.7 44.5 24 44.5c11 0 20.5-8 20.5-20 0-1.3-.1-2.7-.4-4Z"/><path fill="#34A853" d="M6.3 14.7l7 5.1C15 16.1 19.2 13 24 13c3 0 5.7 1.1 7.8 2.9l6.3-6.3C34.5 5.6 29.5 3.5 24 3.5c-7.7 0-14.4 4.4-17.7 11.2Z"/><path fill="#FBBC05" d="M24 44.5c5.4 0 10.3-1.9 14-5.1l-6.5-5.3C29.6 35.6 27 36.5 24 36.5c-5.6 0-10.2-3-11.8-7.5l-7 5.4C8 39.9 15.5 44.5 24 44.5Z"/><path fill="#EA4335" d="M44.5 20H24v8.5h11.8c-.8 2.3-2.4 4.2-4.4 5.5l6.5 5.3c3.8-3.5 6.1-8.7 6.1-15.3 0-1.3-.1-2.7-.4-4Z"/></svg>
      Continue with Google
    </a>
  </div>
</body>
</html>`;

  res.send(html);
});

authRouter.get("/google", (req: Request, res: Response) => {
  const { state } = req.query as { state?: string };

  const url = googleClient.generateAuthUrl({
    access_type: "offline",
    scope: ["openid", "profile", "email"],
    state: state ?? "",
    prompt: "select_account",
  });

  res.redirect(url);
});

authRouter.get("/google/callback", async (req: Request, res: Response) => {
  const { code, state } = req.query as { code?: string; state?: string };

  if (!code) {
    res.status(400).send("Missing code from Google");
    return;
  }

  try {
    const { tokens } = await googleClient.getToken(code);
    googleClient.setCredentials(tokens);

    const ticket = await googleClient.verifyIdToken({
      idToken: tokens.id_token!,
      audience: env.GOOGLE_CLIENT_ID,
    });
    const payload = ticket.getPayload();
    if (!payload || !payload.email) {
      res.status(400).send("Invalid Google token");
      return;
    }

    const existingUsers = await db
      .select()
      .from(users)
      .where(eq(users.email, payload.email))
      .limit(1);

    let userId: string;

    if (existingUsers.length > 0) {
      userId = existingUsers[0]!.id;
      await db
        .update(users)
        .set({
          lastLoginAt: new Date(),
          name: payload.name ?? existingUsers[0]!.name,
          picture: payload.picture ?? existingUsers[0]!.picture,
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
      secure: process.env.NODE_ENV === "production",
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

    res.send(`<!DOCTYPE html>
<html><head><title>Cortex</title>
<style>body{font-family:system-ui,sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;background:#f4f4f6;} .card{background:white;border-radius:16px;padding:2rem;text-align:center;} h2{color:#7f77dd;}</style>
</head><body>
<div class="card">
  <h2>Welcome, ${payload.name ?? payload.email}!</h2>
  <p style="margin-top:1rem;color:#666;">You are logged in to Cortex.</p>
</div>
</body></html>`);
  } catch (err) {
    console.error("Google callback error:", err);
    res.status(500).send("Authentication failed");
  }
});

authRouter.post("/logout", async (req: Request, res: Response) => {
  const sessionId = req.cookies?.cortex_session as string | undefined;
  if (sessionId) {
    await db
      .delete(cortexSessions)
      .where(eq(cortexSessions.id, sessionId))
      .catch(() => {});
  }
  res.clearCookie("cortex_session");
  res.json({ ok: true });
});
