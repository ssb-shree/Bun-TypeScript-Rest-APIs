import { Router } from "express";

const router = Router();

import { getAllSessionController, deleteOneSession } from "../controllers/session.controller.ts";
import { checkAuth } from "../middlewares/auth.middleware.ts";

router.get("/", checkAuth, getAllSessionController);

router.delete("/:id", checkAuth, deleteOneSession);

export default router;
