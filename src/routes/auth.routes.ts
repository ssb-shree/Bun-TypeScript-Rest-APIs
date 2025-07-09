import { Router } from "express";

const router = Router();

import { registerController } from "../controllers/auth.controller";

router.post("/register", registerController);

export default router;
