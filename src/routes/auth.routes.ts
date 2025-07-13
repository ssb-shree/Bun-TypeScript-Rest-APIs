import { Router } from "express";

const router = Router();

import {
	registerController,
	loginController,
	logoutController,
	refreshController,
	verifyUserController,
	sendPasswordForgotEmailController,
	passwordResetController,
} from "../controllers/auth.controller";

import { checkAuth } from "../middlewares/auth.middleware";

router.post("/register", registerController);

router.post("/login", loginController);

router.get("/logout", checkAuth, logoutController);

router.get("/refresh", refreshController);

router.get("/verify/email/:code", verifyUserController);

router.post("/forgot-password", sendPasswordForgotEmailController);

router.post("/reset-password", passwordResetController);

export default router;
