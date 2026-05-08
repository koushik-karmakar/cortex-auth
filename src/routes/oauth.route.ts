import { Router, type Request, type Response } from "express";
import { validateClient } from "../middlewares/validateClient.js";
import { oauthController } from "../controllers/oauth.controller.js";
export const oauthRouter = Router();
oauthRouter.get("/authorize", oauthController.authorize.bind(oauthController));
oauthRouter.post(
  "/token",
  validateClient,
  oauthController.authToken.bind(oauthController),
);
oauthRouter.post(
  "/revoke",
  validateClient,
  oauthController.authRevoke.bind(oauthController),
);
