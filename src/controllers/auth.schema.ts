import z from "zod";

const loginSchema = z.object({
	email: z.string().email().min(1).max(255),
	username: z.string().min(1).max(255),
	password: z.string().min(6).max(255),
	userAgent: z.string().optional(),
});

const registerSchema = loginSchema
	.extend({
		confirmPassword: z.string().min(6).max(255),
	})
	.refine(data => data.password === data.confirmPassword, {
		message: "passwords did not match",
		path: ["confirmPassword"],
	});

const verificationCodeSchema = z.string().min(6).max(24);

export { registerSchema, loginSchema, verificationCodeSchema };
