import jwt from "jsonwebtoken";
import config from "config";

import type { NextFunction, Request, Response } from "express";

export type accessTokenPayload = {
	userID: string;
	sessionID: string;
	iat?: number;
	exp?: number;
};

// attaching a new property to the express req object
export interface AuthenticatedRequest extends Request {
	user?: accessTokenPayload;
}

import asyncHandler from "../utils/asyncHandler";
import ApiError from "../utils/apiError";
import { UNAUTHORIZED } from "../constants/status-codes";
import logger from "../utils/logger";

export const checkAuth = asyncHandler(async (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
	const accessToken = req.cookies.accessToken as string | undefined;
	if (!accessToken) {
		logger.warn("access token not found");
		throw new ApiError(UNAUTHORIZED, "No Token provided");
	}

	const decodedPayload = jwt.verify(accessToken, config.get<string>("accessSecret")) as accessTokenPayload;
	if (!decodedPayload) {
		logger.warn("failed to decode the jwt token");
		throw new ApiError(UNAUTHORIZED, "Unauthorized");
	}

	req.user = decodedPayload;
	next();
});
