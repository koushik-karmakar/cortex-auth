import { Router } from "express";
import { authController } from "../controllers/auth.controller.js";
export const authRouter = Router();
authRouter.get("/login", authController.login.bind(authController));
authRouter.get("/google", authController.generateAuthUrl.bind(authController));
authRouter.get(
  "/google/callback",
  authController.googleCallBack.bind(authController),
);
authRouter.get(
  "/logout",
  authController.clearCookiesRedirect.bind(authController),
);
authRouter.post("/logout", authController.clearCookies.bind(authController));
authRouter.get("/admin/login", authController.adminLogin.bind(authController));
authRouter.get(
  "/admin/google",
  authController.adminGoogleClient.bind(authController),
);
authRouter.get(
  "/admin/google/callback",
  authController.admin_session.bind(authController),
);
authRouter.get(
  "/admin/logout",
  authController.adminLogout.bind(authController),
);
