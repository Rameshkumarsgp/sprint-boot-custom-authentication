package org.example.sprintbootcustomauthentication.shared;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.ContentCachingRequestWrapper;
import org.springframework.web.util.ContentCachingResponseWrapper;

import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Component
@EnableConfigurationProperties(HttpLoggingProperties.class)
@Order(Ordered.HIGHEST_PRECEDENCE + 10)
@RequiredArgsConstructor
public class RequestLoggingFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger("HTTP");

    static final String REQUEST_ID_HEADER = "X-Request-Id";
    private static final String MDC_KEY = "requestId";

    private static final Pattern SAFE_REQUEST_ID = Pattern.compile("[A-Za-z0-9._-]{1,64}");
    private static final Pattern SECRET_FIELDS = Pattern.compile(
            "(\"(?:otp|password|token|accessToken|refreshToken)\"\\s*:\\s*\")[^\"]*(\")",
            Pattern.CASE_INSENSITIVE);
    private static final Pattern MOBILE_FIELD = Pattern.compile(
            "(\"mobileNumber\"\\s*:\\s*\")([^\"]*)(\")");

    private final HttpLoggingProperties properties;

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return request.getRequestURI().startsWith("/actuator");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        String requestId = resolveRequestId(request.getHeader(REQUEST_ID_HEADER));
        MDC.put(MDC_KEY, requestId);
        response.setHeader(REQUEST_ID_HEADER, requestId);

        ContentCachingRequestWrapper wrappedRequest =
                new ContentCachingRequestWrapper(request, properties.maxBodyLength());
        ContentCachingResponseWrapper wrappedResponse = new ContentCachingResponseWrapper(response);
        long start = System.nanoTime();

        try {
            filterChain.doFilter(wrappedRequest, wrappedResponse);
        } finally {
            try {
                logExchange(request, wrappedRequest, wrappedResponse,
                        (System.nanoTime() - start) / 1_000_000);
            } finally {
                wrappedResponse.copyBodyToResponse();
                MDC.remove(MDC_KEY);
            }
        }
    }

    private void logExchange(HttpServletRequest request, ContentCachingRequestWrapper wrappedRequest,
                             ContentCachingResponseWrapper wrappedResponse, long durationMs) {
        int status = wrappedResponse.getStatus();
        StringBuilder line = new StringBuilder()
                .append(request.getMethod()).append(' ').append(request.getRequestURI())
                .append(" -> ").append(status)
                .append(" (").append(durationMs).append(" ms)")
                .append(" ip=").append(request.getRemoteAddr());

        if (properties.logBodies()) {
            appendBody(line, " req=", wrappedRequest.getContentAsByteArray(),
                    wrappedRequest.getCharacterEncoding());
            if (status >= 400) {
                appendBody(line, " res=", wrappedResponse.getContentAsByteArray(),
                        wrappedResponse.getCharacterEncoding());
            }
        }

        if (status >= 500) {
            log.error("{}", line);
        } else if (status >= 400) {
            log.warn("{}", line);
        } else {
            log.info("{}", line);
        }
    }

    private void appendBody(StringBuilder line, String label, byte[] bytes, String encoding) {
        if (bytes.length == 0) {
            return;
        }
        Charset charset = encoding != null ? Charset.forName(encoding) : StandardCharsets.UTF_8;
        line.append(label).append(truncate(mask(new String(bytes, charset))));
    }

    private String truncate(String text) {
        int max = properties.maxBodyLength();
        return text.length() > max ? text.substring(0, max) + "...(truncated)" : text;
    }

    static String resolveRequestId(String incoming) {
        if (incoming != null && SAFE_REQUEST_ID.matcher(incoming).matches()) {
            return incoming;
        }
        return UUID.randomUUID().toString();
    }

    static String mask(String body) {
        String masked = SECRET_FIELDS.matcher(body).replaceAll("$1***$2");
        return MOBILE_FIELD.matcher(masked).replaceAll(match ->
                Matcher.quoteReplacement(match.group(1) + maskDigits(match.group(2)) + match.group(3)));
    }

    private static String maskDigits(String value) {
        if (value.length() <= 4) {
            return "****";
        }
        return "*".repeat(value.length() - 4) + value.substring(value.length() - 4);
    }
}
