import type { Response, CookieOptions } from "express";

import config from "config";
const status = config.get<string>("status");

import { daysFromNow, minsFromNow } from "./date";

const options: CookieOptions = {
  sameSite: "strict",
  httpOnly: true,
  secure: status === "PROD",
};

const getAccessTokenOptions = (): CookieOptions => ({ ...options, expires: minsFromNow(30) });
const getRefreshTokenOptions = (): CookieOptions => ({ ...options, expires: daysFromNow(30) });

type params = {
  res: Response;
  accessToken: string;
  refreshToken: string;
};

export const setAuthCookies = ({ res, accessToken, refreshToken }: params): Response => {
  return res
    .cookie("accessToken", accessToken, getAccessTokenOptions())
    .cookie("refreshToken", refreshToken, getRefreshTokenOptions());
};
