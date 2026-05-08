import { Router } from "express";
import { userController } from "../controllers/user.controller.js";
export const userinfoRouter = Router();
userinfoRouter.get("/", userController.userInfo.bind(userController));
