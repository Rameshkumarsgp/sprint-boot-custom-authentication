package org.example.sprintbootcustomauthentication.auth;

import lombok.extern.slf4j.Slf4j;
import org.example.sprintbootcustomauthentication.shared.InvalidMobileNumberException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.web.ErrorResponse;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.LinkedHashMap;
import java.util.Map;

@Slf4j
@RestControllerAdvice
class ApiExceptionHandler {

    @ExceptionHandler(MethodArgumentNotValidException.class)
    ResponseEntity<ApiError> handleValidation(MethodArgumentNotValidException ex) {
        Map<String, String> details = new LinkedHashMap<>();
        ex.getBindingResult().getFieldErrors()
                .forEach(e -> details.putIfAbsent(e.getField(), e.getDefaultMessage()));
        return ResponseEntity.badRequest().body(new ApiError("VALIDATION_FAILED", details));
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    ResponseEntity<ApiError> handleUnreadable(HttpMessageNotReadableException ex) {
        return ResponseEntity.badRequest().body(ApiError.of("MALFORMED_REQUEST"));
    }

    @ExceptionHandler(Exception.class)
    ResponseEntity<ApiError> handleUnExpected(Exception ex) {
        if (ex instanceof ErrorResponse errorResponse) {
            HttpStatus status = HttpStatus.resolve(errorResponse.getStatusCode().value());
            return ResponseEntity.status(errorResponse.getStatusCode())
                    .body(ApiError.of(status != null ? status.name() : "ERROR"));
        }
        log.error("Unexpected error: ", ex);
        return  ResponseEntity.internalServerError().body(ApiError.of("INTERNAL_ERROR"));
    }

    @ExceptionHandler(AccessDeniedException.class)
    ResponseEntity<ApiError> handleAccessDenied(AccessDeniedException ex) {
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(ApiError.of("FORBIDDEN"));
    }

    @ExceptionHandler(InvalidMobileNumberException.class)
    ResponseEntity<ApiError> handleInvalidMobile(InvalidMobileNumberException ex) {
        return ResponseEntity.badRequest()
                .body(new ApiError("VALIDATION_FAILED", Map.of("mobileNumber", "invalid mobile number")));
    }
}

