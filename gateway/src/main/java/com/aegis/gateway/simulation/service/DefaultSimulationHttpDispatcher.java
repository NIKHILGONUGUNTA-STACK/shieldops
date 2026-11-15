package com.aegis.gateway.simulation.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;

@Component
public class DefaultSimulationHttpDispatcher implements SimulationHttpDispatcher {

    private static final Logger log = LoggerFactory.getLogger(DefaultSimulationHttpDispatcher.class);

    private final HttpClient httpClient;

    public DefaultSimulationHttpDispatcher() {
        this.httpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(5))
            .build();
    }

    @Override
    public DispatchResult dispatch(
        String method,
        String url,
        Map<String, String> headers,
        String body,
        int timeoutMs
    ) {
        long start = System.currentTimeMillis();
        try {
            URI uri = URI.create(url);
            String host = uri.getHost();
            if (host == null || (!host.equals("localhost") && !host.equals("127.0.0.1") && !host.equals("::1"))) {
                log.warn("Safety invariant violation: simulation target must be localhost, received host='{}'", host);
                return new DispatchResult(400, 0, 0, Map.of(), "Target host must be localhost");
            }

            HttpRequest.Builder reqBuilder = HttpRequest.newBuilder()
                .uri(uri)
                .timeout(Duration.ofMillis(timeoutMs > 0 ? timeoutMs : 5000));

            if (headers != null) {
                headers.forEach(reqBuilder::header);
            }

            HttpRequest.BodyPublisher publisher = body != null && !body.isEmpty()
                ? HttpRequest.BodyPublishers.ofString(body)
                : HttpRequest.BodyPublishers.noBody();

            switch (method.toUpperCase()) {
                case "POST" -> reqBuilder.POST(publisher);
                case "PUT" -> reqBuilder.PUT(publisher);
                case "DELETE" -> reqBuilder.DELETE();
                default -> reqBuilder.GET();
            }

            HttpResponse<String> resp = httpClient.send(reqBuilder.build(), HttpResponse.BodyHandlers.ofString());
            long duration = System.currentTimeMillis() - start;

            Map<String, String> respHeaders = new HashMap<>();
            resp.headers().map().forEach((k, v) -> {
                if (k != null && v != null && !v.isEmpty()) {
                    respHeaders.put(k, v.get(0));
                }
            });

            int size = resp.body() != null ? resp.body().getBytes().length : 0;
            return new DispatchResult(resp.statusCode(), duration, size, respHeaders, null);

        } catch (Exception e) {
            long duration = System.currentTimeMillis() - start;
            log.debug("Simulation dispatch to {} encountered: {}", url, e.getMessage());
            return new DispatchResult(503, duration, 0, Map.of(), e.getMessage());
        }
    }
}

