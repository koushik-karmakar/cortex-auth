import type { Request, Response } from "express";
import { verifyToken } from "../utils/jwt.js";
import { db } from "../db/db.js";
import { accessTokens, users } from "../db/schema.js";
import { eq, and } from "drizzle-orm";
class User_controller {
  userInfo = async (req: Request, res: Response) => {
    const authHeader = req.headers.authorization;
    if (!authHeader?.startsWith("Bearer ")) {
      res.status(401).json({ error: "unauthorized" });
      return;
    }
    const token = authHeader.slice(7);
    try {
      const payload = await verifyToken(token);

      const [stored] = await db
        .select()
        .from(accessTokens)
        .where(
          and(
            eq(accessTokens.id, payload.jti!),
            eq(accessTokens.revoked, false),
          ),
        )
        .limit(1);

      if (!stored || stored.expiresAt < new Date()) {
        res.status(401).json({ error: "token_expired" });
        return;
      }

      const [user] = await db
        .select()
        .from(users)
        .where(eq(users.id, payload.sub))
        .limit(1);

      if (!user) {
        res.status(401).json({ error: "user_not_found" });
        return;
      }

      res.json({
        sub: user.id,
        email: user.email,
        name: user.name,
        picture: user.picture ?? null,
      });
    } catch {
      res.status(401).json({ error: "invalid_token" });
    }
  };
}

export const userController = new User_controller();
