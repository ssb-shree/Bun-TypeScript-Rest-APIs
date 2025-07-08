import { type ErrorRequestHandler } from "express";

import logger from "../utils/logger";

export const errorHandler: ErrorRequestHandler = (err, req, res, next) => {
  logger.error({
    message: err.message || "Unknown Error",
    stack: err.stack,
    path: req.path,
    method: req.method,
  });
  res.status(500).json({ message: "Internal Server Error", success: false });
};
