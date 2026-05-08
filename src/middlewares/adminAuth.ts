import type { Request, Response, NextFunction } from "express";
import { db } from "../db/db.js";
import { adminSessions } from "../db/schema.js";
import { eq } from "drizzle-orm";

declare global {
  namespace Express {
    interface Request {
      adminUser?: {
        email: string;
        name: string;
        picture?: string | null;
      };
    }
  }
}

export async function requireAdmin(
  req: Request,
  res: Response,
  next: NextFunction,
) {
  const sessionId = req.cookies?.cortex_admin_session as string | undefined;

  if (!sessionId) {
    if (req.path.startsWith("/api")) {
      res.status(401).json({ error: "Unauthorized" });
    } else {
      res.redirect("/auth/admin/login");
    }
    return;
  }

  try {
    const [session] = await db
      .select()
      .from(adminSessions)
      .where(eq(adminSessions.id, sessionId))
      .limit(1);

    if (!session || session.expiresAt < new Date()) {
      res.clearCookie("cortex_admin_session");
      if (req.path.startsWith("/api")) {
        res.status(401).json({ error: "Session expired" });
      } else {
        res.redirect("/auth/admin/login");
      }
      return;
    }

    req.adminUser = {
      email: session.email,
      name: session.name,
      picture: session.picture,
    };
    next();
  } catch (err) {
    console.error("Admin auth error:", err);
    res.redirect("/auth/admin/login");
  }
}
