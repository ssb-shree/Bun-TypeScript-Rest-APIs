export const OK = 200;
export const CREATED = 201;
export const ACCEPTED = 202;
export const NO_CONTENT = 204;

export const BAD_REQUEST = 400;
export const UNAUTHORIZED = 401;
export const FORBIDDEN = 403;
export const NOT_FOUND = 404;
export const CONFLICT = 409;
export const UNPROCESSABLE_CONTENT = 422;
export const TOO_MANY_REQUESTS = 429;

export const INTERNAL_SERVER_ERROR = 500;
export const NOT_IMPLEMENTED = 501;
export const BAD_GATEWAY = 502;
export const SERVICE_UNAVAILABLE = 503;

export type HttpStatusCode =
  | typeof OK
  | typeof CREATED
  | typeof ACCEPTED
  | typeof NO_CONTENT
  | typeof BAD_REQUEST
  | typeof UNAUTHORIZED
  | typeof FORBIDDEN
  | typeof NOT_FOUND
  | typeof CONFLICT
  | typeof UNPROCESSABLE_CONTENT
  | typeof TOO_MANY_REQUESTS
  | typeof INTERNAL_SERVER_ERROR
  | typeof NOT_IMPLEMENTED
  | typeof BAD_GATEWAY
  | typeof SERVICE_UNAVAILABLE;
