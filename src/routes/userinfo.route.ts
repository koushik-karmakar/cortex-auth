import { Router, type Request, type Response } from "express";
import { db } from "../db/db.js";
import { users, accessTokens } from "../db/schema.js";
import { eq, and } from "drizzle-orm";
import { verifyToken } from "../utils/jwt.js";

export const userinfoRouter = Router();

userinfoRouter.get("/", async (req: Request, res: Response) => {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith("Bearer ")) {
    res.status(401).json({ error: "unauthorized" });
    return;
  }

  const token = authHeader.slice(7);

  let payload;
  try {
    payload = await verifyToken(token);
  } catch {
    res.status(401).json({ error: "invalid_token" });
    return;
  }

  if (payload.jti) {
    const [stored] = await db
      .select()
      .from(accessTokens)
      .where(
        and(eq(accessTokens.id, payload.jti), eq(accessTokens.revoked, false)),
      )
      .limit(1);

    if (!stored || stored.expiresAt < new Date()) {
      res.status(401).json({ error: "invalid_token" });
      return;
    }
  }

  const [user] = await db
    .select()
    .from(users)
    .where(eq(users.id, payload.sub!))
    .limit(1);

  if (!user) {
    res.status(404).json({ error: "user_not_found" });
    return;
  }

  res.json({
    sub: user.id,
    email: user.email,
    name: user.name,
    picture: user.picture ?? null,
  });
});
