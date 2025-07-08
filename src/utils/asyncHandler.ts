import { type NextFunction, type Request, type Response } from "express";

type AsyncController = (req: Request, res: Response, next: NextFunction) => Promise<any>;

const asyncHandler = (controller: AsyncController): AsyncController => {
  return async (req, res, next) => {
    return Promise.resolve(controller(req, res, next)).catch((err) => next(err));
  };
};

export default asyncHandler;
