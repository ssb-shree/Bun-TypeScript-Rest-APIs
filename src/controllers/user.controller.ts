import { OK, UNAUTHORIZED } from "../constants/status-codes";
import type { AuthenticatedRequest } from "../middlewares/auth.middleware";
import { User } from "../models/user.model";
import ApiError from "../utils/apiError";
import asyncHandler from "../utils/asyncHandler";

const getUserInfo = asyncHandler(async (req: AuthenticatedRequest, res) => {
	const userDetails = req.user;

	if (!userDetails) throw new ApiError(UNAUTHORIZED, "Unauthorized");

	const user = await User.findById(userDetails.userID).select("-password");

	res.status(OK).json({ user, message: "user fetched successfully", success: true });
});

export { getUserInfo };
