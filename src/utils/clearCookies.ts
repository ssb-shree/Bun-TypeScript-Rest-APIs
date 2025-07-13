import type { Request, Response } from "express";

import config from "config";

export const clearCookies = (req: Request, res: Response) => {
	for (const cookieName in req.cookies) {
		res.clearCookie(cookieName, {
			httpOnly: true,
			sameSite: "strict",
			secure: config.get<string>("status") === "DEV",
		});
	}
};
