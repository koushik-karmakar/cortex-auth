import type { Request, Response, NextFunction } from "express";
import { db } from "../db/db.js";
import { oauthClients } from "../db/schema.js";
import { eq } from "drizzle-orm";
import crypto from "node:crypto";

declare global {
  namespace Express {
    interface Request {
      oauthClient?: typeof oauthClients.$inferSelect;
      sessionUser?: {
        id: string;
        email: string;
        name: string;
        picture?: string | null;
      };
    }
  }
}

export async function validateClient(
  req: Request,
  res: Response,
  next: NextFunction,
) {
  let clientId: string | undefined;
  let clientSecret: string | undefined;

  const authHeader = req.headers.authorization;
  if (authHeader?.startsWith("Basic ")) {
    const decoded = Buffer.from(authHeader.slice(6), "base64").toString("utf8");
    [clientId, clientSecret] = decoded.split(":", 2);
  } else {
    clientId = req.body?.client_id as string | undefined;
    clientSecret = req.body?.client_secret as string | undefined;
  }

  if (!clientId || !clientSecret) {
    res.status(401).json({
      error: "invalid_client",
      error_description: "Missing client credentials",
    });
    return;
  }

  const [client] = await db
    .select()
    .from(oauthClients)
    .where(eq(oauthClients.clientId, clientId))
    .limit(1);

  if (!client) {
    res
      .status(401)
      .json({ error: "invalid_client", error_description: "Unknown client" });
    return;
  }

  const inputHash = crypto
    .createHash("sha256")
    .update(clientSecret)
    .digest("hex");
  const storedHash = crypto
    .createHash("sha256")
    .update(client.clientSecret)
    .digest("hex");
  const valid = crypto.timingSafeEqual(
    Buffer.from(inputHash),
    Buffer.from(storedHash),
  );

  if (!valid) {
    res.status(401).json({
      error: "invalid_client",
      error_description: "Invalid client secret",
    });
    return;
  }

  req.oauthClient = client;
  next();
}
