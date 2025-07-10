import { Router } from "express";

const router = Router();

import { registerController, loginController, logoutController } from "../controllers/auth.controller";

import { checkAuth } from "../middlewares/auth.middleware";

router.post("/register", registerController);

router.post("/login", loginController);

router.get("/logout", checkAuth, logoutController);

export default router;
