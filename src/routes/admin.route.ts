import { Router } from "express";
import { requireAdmin } from "../middlewares/adminAuth.js";
import { adminController } from "../controllers/admin.controller.js";
const adminRouter = Router();
adminRouter.get("/", requireAdmin, adminController.admin.bind(adminController));
adminRouter.get(
  "/api/clients",
  requireAdmin,
  adminController.adminGetAplication.bind(adminController),
);
adminRouter.post(
  "/api/clients",
  requireAdmin,
  adminController.adminPostAplication.bind(adminController),
);
adminRouter.delete(
  "/api/clients/:clientId",
  requireAdmin,
  adminController.adminDeleteAplication.bind(adminController),
);
export { adminRouter };
