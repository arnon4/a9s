const std = @import("std");

/// Common AWS error codes returned across all services.
/// Names match the error code strings exactly — @errorName(err) gives the AWS code.
pub const AwsCommonError = error{
    AccessDenied,
    AccessDeniedException,
    ExpiredToken,
    ExpiredTokenException,
    InvalidClientTokenId,
    InternalFailure,
    InternalError,
    InternalServiceError,
    NotAuthorized,
    OptInRequired,
    RequestAbortedException,
    RequestExpired,
    RequestTimeoutException,
    ServiceUnavailable,
    ServiceUnavailableException,
    Throttling,
    ThrottlingException,
    RequestThrottled,
    SlowDown,
    UnknownAwsError,
};

/// Map an AWS error code string to AwsCommonError using comptime name matching.
/// Returns null if code does not match any known common error.
pub fn fromCode(code: []const u8) ?AwsCommonError {
    inline for (@typeInfo(AwsCommonError).error_set.?) |entry| {
        if (std.mem.eql(u8, entry.name, code)) return @field(AwsCommonError, entry.name);
    }
    return null;
}

/// Map an HTTP status code to a common AWS error when no response body is available
/// (e.g. HEAD requests).
pub fn fromStatus(status: std.http.Status) AwsCommonError {
    return switch (status) {
        .unauthorized => error.NotAuthorized,
        .forbidden => error.AccessDenied,
        .request_timeout => error.RequestTimeoutException,
        .too_many_requests => error.ThrottlingException,
        .internal_server_error => error.InternalFailure,
        .service_unavailable => error.ServiceUnavailable,
        else => error.UnknownAwsError,
    };
}
