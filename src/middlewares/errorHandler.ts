import { type ErrorRequestHandler, type Response } from "express";

import config from "config";

import logger from "../utils/logger";
import { BAD_REQUEST, INTERNAL_SERVER_ERROR } from "../constants/status-codes";
import { z } from "zod";
import ApiError from "../utils/apiError";
import { clearCookies } from "../utils/clearCookies";

const REFRESH_PATH = "/auth/refresh";

const zodErrorHandler = (res: Response, error: z.ZodError) => {
	// error.issues object has path which is field and message is the reason why parsing failed
	const errors = error.issues.map(err => ({ path: err.path.join(","), message: err.message }));
	res.status(BAD_REQUEST).json({ message: "Invalid user data", errors, success: false });
};

const apiErrorHandler = (res: Response, error: ApiError) => {
	res.status(error.statusCode).json({ message: error.message, errorCode: error.errorCode });
};

export const errorHandler: ErrorRequestHandler = (err, req, res, next) => {
	logger.error({
		message: err.message || "Unknown Error",
		stack: err.stack,
		path: req.path,
		method: req.method,
	});

	if (req.path == REFRESH_PATH) {
		return clearCookies(req, res);
	}

	if (err instanceof z.ZodError) {
		return zodErrorHandler(res, err);
	}

	if (err instanceof ApiError) {
		return apiErrorHandler(res, err);
	}

	res.status(INTERNAL_SERVER_ERROR).json({ message: "Internal Server Error", success: false });
};
