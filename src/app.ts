import express, { type NextFunction, type Request, type Response } from "express";

import config from "config";
import morgan from "morgan"; // http logger
import cors from "cors";
import cookieParser from "cookie-parser";

import { errorHandler } from "./middlewares/errorHandler";
import asyncHandler from "./utils/asyncHandler";

import { OK } from "./constants/status-codes";

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(
	cors({
		origin: config.get<string>("origin"),
		credentials: true,
	}),
);
app.use(cookieParser());

app.use(
	morgan(
		"\x1b[36m:date[web]\x1b[0m \x1b[33m:method\x1b[0m (\x1b[34m:url\x1b[0m) Status[\x1b[32m:status\x1b[0m] - [\x1b[35m:response-time ms\x1b[0m]",
	),
);

// health check route
app.get(
	"/ping",
	asyncHandler(async (req: Request, res: Response, next: NextFunction) => res.status(OK).send("pong")),
);

// router imports
import authRouter from "./routes/auth.routes";
import userRouter from "./routes/user.routes";
import sessionRouter from "./routes/session.routes";

//routes declaration
app.use("/auth", authRouter);
app.use("/user", userRouter);
app.use("/sessions", sessionRouter);

app.use(errorHandler);

export default app;
