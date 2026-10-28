package com.aegis.gateway.specs;

/**
 * Exception thrown when an uploaded OpenAPI specification fails structural,
 * version, security, or complexity validation.
 */
public class OpenApiValidationException extends RuntimeException {

    private final String errorDetail;

    public OpenApiValidationException(String message) {
        super(message);
        this.errorDetail = message;
    }

    public OpenApiValidationException(String message, String errorDetail) {
        super(message);
        this.errorDetail = errorDetail;
    }

    public String getErrorDetail() {
        return errorDetail;
    }
}

