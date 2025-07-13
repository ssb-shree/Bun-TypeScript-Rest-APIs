import { Resend } from "resend";

import config from "config";
import logger from "./logger";
import ApiError from "./apiError";

import { INTERNAL_SERVER_ERROR } from "../constants/status-codes";

const resend = new Resend(config.get<string>("resendApiKey"));

type params = {
	to: string;
	subject: string;
	text: string;
	html: string;
};

export const sendMail = async ({ to, subject, text, html }: params) => {
	const from = config.get<string>("fromAddress");

	// if in dev use the test mail add provided by resend else use the clients mail add
	config.get<string>("status") == "DEV" ? (to = "deleiverd@resend.dev") : null;

	return await resend.emails.send({ from, to, subject, text, html });
};
