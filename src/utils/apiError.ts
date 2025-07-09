import type ApiErrorCode from "../constants/apiErrorCode";
import type { HttpStatusCode } from "../constants/status-codes";

class ApiError extends Error {
  constructor(public statusCode: HttpStatusCode, override message: string, public errorCode?: ApiErrorCode) {
    super(message);
  }
}

export default ApiError;
