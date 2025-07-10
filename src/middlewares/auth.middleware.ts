import jwt from "jsonwebtoken";
import config from "config";

import type { NextFunction, Request, Response } from "express";

export type DecodedToken = {
	userID: string;
	sessionID: string;
	iat?: number;
	exp?: number;
};

// attaching a new property to the express req object
export interface AuthenticatedRequest extends Request {
	user?: DecodedToken;
}

import asyncHandler from "../utils/asyncHandler";
import ApiError from "../utils/apiError";
import { UNAUTHORIZED } from "../constants/status-codes";
import logger from "../utils/logger";

export const checkAuth = asyncHandler(async (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
	const { accessToken, refreshToken } = req.cookies;
	if (!accessToken) {
		logger.warn("access token not found");
		throw new ApiError(UNAUTHORIZED, "No Token provided");
	}

	const decodedPayload = jwt.verify(accessToken, config.get<string>("accessSecret")) as DecodedToken;
	if (!decodedPayload) {
		logger.warn("failed to decode the jwt token");
		throw new ApiError(UNAUTHORIZED, "Unauthorized");
	}

	req.user = decodedPayload;
	next();
});
