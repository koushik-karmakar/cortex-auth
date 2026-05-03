import crypto from "node:crypto";

export function verifyPKCE(
  codeVerifier: string,
  codeChallenge: string,
  method: string,
): boolean {
  if (method === "S256") {
    const computed = crypto
      .createHash("sha256")
      .update(codeVerifier)
      .digest("base64url");
    return computed === codeChallenge;
  }

  return codeVerifier === codeChallenge;
}

export function generateSecureToken(bytes = 32): string {
  return crypto.randomBytes(bytes).toString("base64url");
}
