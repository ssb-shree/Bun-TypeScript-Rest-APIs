import { Router } from "express";

const router = Router();

import {
	registerController,
	loginController,
	logoutController,
	refreshController,
} from "../controllers/auth.controller";

import { checkAuth } from "../middlewares/auth.middleware";

router.post("/register", registerController);

router.post("/login", loginController);

router.get("/logout", checkAuth, logoutController);

router.get("/refresh", refreshController);

export default router;
