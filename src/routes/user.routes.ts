import { Router } from "express";

const router = Router();

import { getUserInfo } from "../controllers/user.controller";
import { checkAuth } from "../middlewares/auth.middleware";

router.get("/", checkAuth, getUserInfo);

export default router;
