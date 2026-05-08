import express from "express";
import cookieParser from "cookie-parser";
import cors from "cors";
import { env } from "./env.js";
import { authRouter } from "./routes/auth.route.js";
import { oauthRouter } from "./routes/oauth.route.js";
import { userinfoRouter } from "./routes/userinfo.route.js";
import oidcController from "./controllers/oidc.controller.js";
import { adminRouter } from "./routes/admin.route.js";

declare global {
  namespace Express {
    interface Request {
      adminUser?: { email: string; name: string; picture?: string | null };
    }
  }
}

const app = express();

// ==================cors ============================
app.use(
  cors({
    origin: true,
    credentials: true,
  }),
);
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser(env.SESSION_SECRET));

// ================ OIDC discovery =====================
app.get(
  "/.well-known/openid-configuration",
  oidcController.oidc.bind(oidcController),
);

// ================== Auth + OAuth + Userinfo ==========================
app.use("/auth", authRouter);
app.use("/oauth", oauthRouter);
app.use("/userinfo", userinfoRouter);

// ================== Admin dashboard (requires session) ==================
app.use("/admin", adminRouter);
export default app;
