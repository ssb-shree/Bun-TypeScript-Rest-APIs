import z from "zod";
import jwt from "jsonwebtoken";

import config from "config";
import asyncHandler from "../utils/asyncHandler";

import { User } from "../models/user.model";
import { VerificationCode } from "../models/verification.model";
import { Session } from "../models/session.model";

import { CONFLICT, CREATED, OK } from "../constants/status-codes";
import { VerificationCodeType } from "../utils/verificationCode";
import { daysFromNow } from "../utils/date";
import { setAuthCookies } from "../utils/setCookies";
import ApiError from "../utils/apiError";

const registerSchema = z
  .object({
    email: z.string().email().min(1).max(255),
    username: z.string().min(1).max(255),
    password: z.string().min(6).max(255),
    confirmPassword: z.string().min(6).max(255),
    userAgent: z.string().optional(),
  })
  .refine((data) => data.password === data.confirmPassword, {
    message: "passwords did not match",
    path: ["confirmPassword"],
  });

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
  const responsePayload = {
    ID: newUser._id,
    email: newUser.email,
    username: newUser.username,
    userAgent: newUser.userAgent,
  };

  // remove the password field
  // create verification code
  const verificationCode = await VerificationCode.create({
    userID: newUser._id,
    type: VerificationCodeType.EmailVerification,
    expiresAt: daysFromNow(1),
  });

  //create a session
  const session = await Session.create({ userID: newUser._id, userAgent });

  // create a token
  const refreshToken = jwt.sign({ sessionID: session._id }, config.get<string>("refreshSecret"), { expiresIn: "30d" });
  const accessToken = jwt.sign({ sessionID: session._id, userID: newUser._id }, config.get<string>("accessSecret"), {
    expiresIn: "1h",
  });

  // returns an express response object so we can continue the chaining
  return setAuthCookies({ res, accessToken, refreshToken }).status(CREATED).json({ user: responsePayload });
});

export { registerController };
