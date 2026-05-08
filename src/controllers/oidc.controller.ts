import { env } from "../env.js";
import type { Request, Response } from "express";
class OidcController {
  oidc(_req: Request, res: Response) {
    res.status(200).json({
      issuer: env.JWT_ISSUER,
      authorization_endpoint: `${env.APP_URL}/oauth/authorize`,
      token_endpoint: `${env.APP_URL}/oauth/token`,
      userinfo_endpoint: `${env.APP_URL}/userinfo`,
      revocation_endpoint: `${env.APP_URL}/oauth/revoke`,
      scopes_supported: ["openid", "profile", "email"],
      response_types_supported: ["code"],
      grant_types_supported: ["authorization_code", "refresh_token"],
      code_challenge_methods_supported: ["S256", "plain"],
      token_endpoint_auth_methods_supported: [
        "client_secret_basic",
        "client_secret_post",
      ],
    });
  }
}

export default new OidcController();
