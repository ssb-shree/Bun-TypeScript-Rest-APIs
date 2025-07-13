import config from "config";
import jwt from "jsonwebtoken";

import asyncHandler from "../utils/asyncHandler";
import ApiError from "../utils/apiError";
import logger from "../utils/logger";

import { User } from "../models/user.model";
import { VerificationCode } from "../models/verification.model";
import { Session } from "../models/session.model";

import {
	BAD_REQUEST,
	CONFLICT,
	CREATED,
	INTERNAL_SERVER_ERROR,
	NOT_FOUND,
	OK,
	TOO_MANY_REQUESTS,
	UNAUTHORIZED,
} from "../constants/status-codes";
import { VerificationCodeType } from "../utils/verificationCode";

import { daysFromNow, minsAgo, minsFromNow } from "../utils/date";
import { setAuthCookies } from "../utils/setCookies";

import type { AuthenticatedRequest } from "../middlewares/auth.middleware";
import { registerSchema, loginSchema, verificationCodeSchema, emailSchema, forgotPasswordSchema } from "./auth.schema";
import { sendMail } from "../utils/resend";
import { resetPasswordEmailTemplate, verifyEmailTemplate } from "../utils/mailTemplates";
import { hashPassword } from "../utils/bcrypt";
import { clearCookies } from "../utils/clearCookies";

const registerController = asyncHandler(async (req, res) => {
	// validate the request body object
	const { email, username, password, userAgent } = registerSchema.parse({
		...req.body,
		userAgent: req.headers["user-agent"],
	});

	// check if the user already exist
	const userExist = await User.exists({ email, username });
	if (userExist) throw new ApiError(CONFLICT, "Credentials are taken");

	// create user
	const newUser = await User.create({ email, username, password, userAgent });

	// create verification code
	const verificationCode = await VerificationCode.create({
		userID: newUser._id,
		type: VerificationCodeType.EmailVerification,
		expiresAt: daysFromNow(1),
	});

	// send verification mail
	const url = `${config.get<string>("origin")}/auth/verify/email/${verificationCode._id}`;
	const { data, error } = await sendMail({ to: newUser.email, ...verifyEmailTemplate(url) });

	if (error) throw new ApiError(INTERNAL_SERVER_ERROR, "Failed to send a mail");

	//create a session
	const session = await Session.create({ userID: newUser._id, userAgent });

	// create a token
	const refreshToken = jwt.sign({ sessionID: session._id }, config.get<string>("refreshSecret"), { expiresIn: "30d" });
	const accessToken = jwt.sign({ sessionID: session._id, userID: newUser._id }, config.get<string>("accessSecret"), {
		expiresIn: "1h",
	});

	// returns an express response object so we can continue the chaining
	return setAuthCookies({ res, accessToken, refreshToken })
		.status(CREATED)
		.json({ message: "User created", success: true });
});

const loginController = asyncHandler(async (req, res) => {
	const { email, username, password, userAgent } = loginSchema.parse({
		...req.body,
		userAgent: req.headers["user-agent"],
	});

	// find the user by email
	const userExist = await User.findOne({ email });
	if (!userExist) throw new ApiError(NOT_FOUND, "Invalid Email or Password");

	// comapre the password
	const checkPassword = await userExist.comparedPassword(password);
	if (!checkPassword) throw new ApiError(UNAUTHORIZED, "Invalid Email or Password");

	// create a session
	const session = await Session.create({ userID: userExist._id, userAgent });

	// create a token
	const refreshToken = jwt.sign({ sessionID: session._id }, config.get<string>("refreshSecret"), { expiresIn: "30d" });
	const accessToken = jwt.sign({ sessionID: session._id, userID: userExist._id }, config.get<string>("accessSecret"), {
		expiresIn: "1h",
	});

	// return user and tokens
	setAuthCookies({ res, accessToken, refreshToken })
		.status(OK)
		.json({ user: userExist, success: true, message: "Login successfull" });
});

const logoutController = asyncHandler(async (req: AuthenticatedRequest, res) => {
	if (!req.user) {
		logger.error("cant access the user property on express req object");
		throw new ApiError(UNAUTHORIZED, "Unauthorised");
	}
	const { userID, sessionID } = req.user;

	await Session.findByIdAndDelete(sessionID);

	res
		.cookie("accessToken", null, { expires: new Date(Date.now()) })
		.cookie("refreshToken", null, { expires: new Date(Date.now()) })
		.status(OK)
		.json({ success: true, message: "Logged out" });
});

const refreshController = asyncHandler(async (req, res) => {
	const refreshToken = req.cookies.refreshToken as string | undefined;

	type refreshTokenPayload = {
		sessionID?: string;
	};

	if (!refreshToken) throw new ApiError(UNAUTHORIZED, "No refresh token provided");

	const { sessionID } = jwt.verify(refreshToken, config.get<string>("refreshSecret")) as refreshTokenPayload;

	const session = await Session.findById(sessionID);
	if (!(session && session.expiresAt.getTime() > Date.now())) throw new ApiError(UNAUTHORIZED, "Session Ended");

	const user = await User.findById(session.userID).select("-password");
	if (!user) throw new ApiError(UNAUTHORIZED, "Invalid Token");

	// refresh the session if its gonna expire soon
	const needsRefresh: boolean = session.expiresAt.getTime() - Date.now() < Date.now() + 24 * 60 * 60 * 1000;

	if (!needsRefresh) throw new ApiError(BAD_REQUEST, "refresh not needed");

	session.expiresAt = daysFromNow(30);
	await session.save();

	// create a token
	const newRefreshToken = jwt.sign({ sessionID: session._id }, config.get<string>("refreshSecret"), {
		expiresIn: "30d",
	});
	const accessToken = jwt.sign({ sessionID: session._id, userID: user._id }, config.get<string>("accessSecret"), {
		expiresIn: "1h",
	});

	// return user and tokens
	setAuthCookies({ res, accessToken, refreshToken: newRefreshToken })
		.status(OK)
		.json({ user, success: true, message: "Session refreshed successfull" });
});

const verifyUserController = asyncHandler(async (req, res) => {
	const codeID = verificationCodeSchema.parse(req.params.code);

	// get code doc
	const verificationDoc = await VerificationCode.findOne({
		_id: codeID,
		type: VerificationCodeType.EmailVerification,
		expiresAt: { $gt: new Date() },
	});
	if (!verificationDoc) throw new ApiError(NOT_FOUND, "Invalid or Expired verification code");

	// search the usser
	const user = await User.findByIdAndUpdate(verificationDoc.userID, { verified: true }, { new: true });
	if (!user) throw new ApiError(INTERNAL_SERVER_ERROR, "Failed to verify user");

	// delete the doc
	await verificationDoc.deleteOne();

	res.status(OK).json({ success: true, message: "Email Verified" });
});

const sendPasswordForgotEmailController = asyncHandler(async (req, res) => {
	const email = emailSchema.parse(req.body.email);

	// find user
	const user = await User.findOne({ email });
	if (!user) throw new ApiError(NOT_FOUND, `Invalid email`);

	// email rate limit
	const count = await VerificationCode.countDocuments({
		userID: user._id,
		type: VerificationCodeType.PasswordReset,
		createdAt: { $gt: minsAgo(10) },
	});

	if (count >= 1) throw new ApiError(TOO_MANY_REQUESTS, "Too many request");

	//create verification code
	const code = await VerificationCode.create({
		userID: user._id,
		type: VerificationCodeType.PasswordReset,
		expiresAt: minsFromNow(60),
	});
	// send mail
	const url = `${config.get<string>("origin")}/password/reset?code=${code._id}&exp=${minsFromNow(60).getTime()}`;
	const { data, error } = await sendMail({ to: user.email, ...resetPasswordEmailTemplate(url) });
	if (error) throw new ApiError(INTERNAL_SERVER_ERROR, "Failed to send a mail");

	res.status(OK).json({ message: "check your mail to reset password", success: true });
});

const passwordResetController = asyncHandler(async (req, res) => {
	const { password, verificationCode: codeID } = forgotPasswordSchema.parse(req.body);

	const validCode = await VerificationCode.findOne({
		_id: codeID,
		type: VerificationCodeType.PasswordReset,
		expiresAt: { $gt: new Date() },
	});

	if (!validCode) throw new ApiError(NOT_FOUND, "Invalid or Expired code");

	const updatedUser = await User.findOneAndUpdate(
		{ _id: validCode.userID },
		{ password: await hashPassword(password) },
		{ new: true },
	);

	if (!updatedUser) throw new ApiError(INTERNAL_SERVER_ERROR, "Failed to update User");

	await validCode.deleteOne();
	await Session.deleteMany({ userID: updatedUser._id });

	clearCookies(req, res);

	res.status(OK).json({ message: "password changed successfully", success: true });
});

export {
	registerController,
	loginController,
	logoutController,
	refreshController,
	verifyUserController,
	sendPasswordForgotEmailController,
	passwordResetController,
};
