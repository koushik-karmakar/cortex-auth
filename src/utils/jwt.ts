import { SignJWT, jwtVerify, type JWTPayload } from "jose";
import { env } from "../env.js";

const secret = new TextEncoder().encode(env.JWT_SECRET);

export interface TokenPayload extends JWTPayload {
  sub: string;
  email?: string;
  name?: string;
  picture?: string;
  client_id?: string;
  scope?: string;
  jti?: string;
}

export async function signAccessToken(payload: TokenPayload): Promise<string> {
  return new SignJWT(payload)
    .setProtectedHeader({ alg: "HS256", typ: "JWT" })
    .setIssuer(env.JWT_ISSUER)
    .setIssuedAt()
    .setExpirationTime("1h")
    .sign(secret);
}

export async function signIdToken(payload: TokenPayload): Promise<string> {
  return new SignJWT(payload)
    .setProtectedHeader({ alg: "HS256", typ: "JWT" })
    .setIssuer(env.JWT_ISSUER)
    .setIssuedAt()
    .setExpirationTime("1h")
    .sign(secret);
}

export async function signRefreshToken(payload: TokenPayload): Promise<string> {
  return new SignJWT(payload)
    .setProtectedHeader({ alg: "HS256", typ: "JWT" })
    .setIssuer(env.JWT_ISSUER)
    .setIssuedAt()
    .setExpirationTime("30d")
    .sign(secret);
}

export async function verifyToken(token: string): Promise<TokenPayload> {
  const { payload } = await jwtVerify(token, secret, {
    issuer: env.JWT_ISSUER,
  });
  return payload as TokenPayload;
}
