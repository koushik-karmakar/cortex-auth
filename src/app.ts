import express from "express";
import cookieParser from "cookie-parser";
import cors from "cors";
import { env } from "./env.js";
import { authRouter } from "./routes/auth.route.js";
import { oauthRouter } from "./routes/oauth.route.js";
import { userinfoRouter } from "./routes/userinfo.route.js";

const app = express();

app.use(cors({
  origin: true,
  credentials: true,
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser(env.SESSION_SECRET));

app.get("/.well-known/openid-configuration", (_req, res) => {
  res.json({
    issuer: env.JWT_ISSUER,
    authorization_endpoint: `${env.APP_URL}/oauth/authorize`,
    token_endpoint: `${env.APP_URL}/oauth/token`,
    userinfo_endpoint: `${env.APP_URL}/userinfo`,
    revocation_endpoint: `${env.APP_URL}/oauth/revoke`,
    scopes_supported: ["openid", "profile", "email"],
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code", "refresh_token"],
    code_challenge_methods_supported: ["S256", "plain"],
    token_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post"],
  });
});

app.use("/auth", authRouter);
app.use("/oauth", oauthRouter);
app.use("/userinfo", userinfoRouter);

app.post("/admin/clients", async (req, res) => {
  const { db } = await import("./db/db.js");
  const { oauthClients } = await import("./db/schema.js");
  const { v4: uuidv4 } = await import("uuid");
  const crypto = await import("node:crypto");

  const { name, redirectUris, scopes } = req.body as {
    name: string;
    redirectUris: string[];
    scopes?: string[];
  };

  if (!name || !redirectUris?.length) {
    res.status(400).json({ error: "name and redirectUris are required" });
    return;
  }

  const clientId = `cortex_${crypto.randomBytes(16).toString("hex")}`;
  const clientSecret = crypto.randomBytes(32).toString("base64url");

  await db.insert(oauthClients).values({
    id: uuidv4(),
    name,
    clientId,
    clientSecret, 
    redirectUris,
    scopes: scopes ?? ["openid", "profile", "email"],
  });
  res.status(201).json({ clientId, clientSecret, name });
});

app.listen(env.PORT, () => {
  console.log(`Cortex Auth running on http://localhost:${env.PORT}`);
  console.log(`Discovery: http://localhost:${env.PORT}/.well-known/openid-configuration`);
});