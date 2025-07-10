import { Router } from "express";

const router = Router();

import { registerController, loginController } from "../controllers/auth.controller";

router.post("/register", registerController);

router.post("/login", loginController);

export default router;
