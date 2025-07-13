import z from "zod";

const sessionIdSchema = z.string().min(1).max(25);

export { sessionIdSchema };
