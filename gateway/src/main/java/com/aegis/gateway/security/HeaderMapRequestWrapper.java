package com.aegis.gateway.security;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;

import java.util.*;

public class HeaderMapRequestWrapper extends HttpServletRequestWrapper {
    private final Map<String, List<String>> customHeaders = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);

    public HeaderMapRequestWrapper(HttpServletRequest request) {
        super(request);
        Enumeration<String> headerNames = request.getHeaderNames();
        if (headerNames != null) {
            while (headerNames.hasMoreElements()) {
                String name = headerNames.nextElement();
                // Strip all inbound X-Aegis-* headers from external callers for defense-in-depth
                if (name.toLowerCase(Locale.ROOT).startsWith("x-aegis-")) {
                    continue;
                }
                Enumeration<String> values = request.getHeaders(name);
                List<String> list = new ArrayList<>();
                while (values.hasMoreElements()) {
                    list.add(values.nextElement());
                }
                customHeaders.put(name, list);
            }
        }
    }

    public void addHeader(String name, String value) {
        customHeaders.computeIfAbsent(name, k -> new ArrayList<>()).add(value);
    }

    public void setHeader(String name, String value) {
        List<String> list = new ArrayList<>();
        list.add(value);
        customHeaders.put(name, list);
    }

    public void removeHeader(String name) {
        customHeaders.remove(name);
    }

    @Override
    public String getHeader(String name) {
        List<String> values = customHeaders.get(name);
        return (values != null && !values.isEmpty()) ? values.get(0) : null;
    }

    @Override
    public Enumeration<String> getHeaders(String name) {
        List<String> values = customHeaders.get(name);
        return values != null ? Collections.enumeration(values) : Collections.emptyEnumeration();
    }

    @Override
    public Enumeration<String> getHeaderNames() {
        return Collections.enumeration(customHeaders.keySet());
    }
}
