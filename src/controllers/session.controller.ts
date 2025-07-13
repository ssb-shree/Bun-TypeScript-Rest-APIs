import { UNAUTHORIZED, OK, NOT_FOUND } from "../constants/status-codes";
import type { AuthenticatedRequest } from "../middlewares/auth.middleware";
import { Session } from "../models/session.model";
import ApiError from "../utils/apiError";
import asyncHandler from "../utils/asyncHandler";
import { sessionIdSchema } from "./session.schema";

const getAllSessionController = asyncHandler(async (req: AuthenticatedRequest, res) => {
	const userDetails = req.user;
	if (!userDetails) throw new ApiError(UNAUTHORIZED, "Unauthorized");

	const sessions = await Session.find(
		{ userID: userDetails.userID },
		{ _id: 1, userAgent: 1, createdAt: 1 },
		{ sort: { createdAt: -1 } },
	);

	res.status(OK).json({ sessions, message: "sessions fetched successfully", success: true });
});

const deleteOneSession = asyncHandler(async (req: AuthenticatedRequest, res) => {
	const sessionID = sessionIdSchema.parse(req.params.id);

	const deletedSession = await Session.findOneAndDelete({
		_id: sessionID,
		userID: req.user?.userID,
	});

	if (deletedSession == null) throw new ApiError(NOT_FOUND, "Failed to delete session");

	res.status(OK).json({ deletedSession, message: "Session deleted", success: true });
});

export { getAllSessionController, deleteOneSession };
