export default {
	status: process.env.STATUS,
	port: process.env.PORT || 8080,
	uri: process.env.MONGODB_URI,
	origin: process.env.STATUS === "PROD" ? process.env.CLIENT_URL : process.env.DEV_CLIENT_URL,
	accessSecret: process.env.JWT_ACCESS_SECRET,
	refreshSecret: process.env.JWT_REFRESH_SECRET,
	resendApiKey: process.env.RESEND_API_KEY,
	fromAddress: process.env.FROM,
};
