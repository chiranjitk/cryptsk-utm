/**
 * API error taxonomy (LOCKED) — docs/04-API/API_STANDARDS.md §5.
 */

export const ERROR_CODES = {
  VALIDATION_ERROR: 400,
  UNAUTHORIZED: 401,
  FORBIDDEN: 403,
  NOT_FOUND: 404,
  CONFLICT: 409,
  RATE_LIMITED: 429,
  INTERNAL: 500,
} as const;

export type ErrorCode = keyof typeof ERROR_CODES;

export class ApiError extends Error {
  constructor(
    public code: ErrorCode,
    message: string,
    public details?: unknown,
  ) {
    super(message);
    this.name = "ApiError";
  }

  get status(): number {
    return ERROR_CODES[this.code];
  }

  static validation(message: string, details?: unknown) {
    return new ApiError("VALIDATION_ERROR", message, details);
  }
  static unauthorized(message = "Authentication required") {
    return new ApiError("UNAUTHORIZED", message);
  }
  static forbidden(message = "You do not have permission to perform this action") {
    return new ApiError("FORBIDDEN", message);
  }
  static notFound(message = "Resource not found") {
    return new ApiError("NOT_FOUND", message);
  }
  static conflict(message: string, details?: unknown) {
    return new ApiError("CONFLICT", message, details);
  }
  static rateLimited(message = "Rate limit exceeded") {
    return new ApiError("RATE_LIMITED", message);
  }
  static internal(message = "Internal server error") {
    return new ApiError("INTERNAL", message);
  }
}
