package com.aegis.gateway.simulation.service;

import java.util.Map;

public interface SimulationHttpDispatcher {

    record DispatchResult(
        int statusCode,
        long responseTimeMs,
        int responseSizeBytes,
        Map<String, String> responseHeaders,
        String error
    ) {
        public boolean isSuccess() {
            return statusCode >= 200 && statusCode < 300;
        }

        public boolean isClientError() {
            return statusCode >= 400 && statusCode < 500;
        }

        public boolean isServerError() {
            return statusCode >= 500;
        }
    }

    DispatchResult dispatch(
        String method,
        String url,
        Map<String, String> headers,
        String body,
        int timeoutMs
    );
}

