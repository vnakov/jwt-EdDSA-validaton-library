package com.security.jwt.filter;

import com.nimbusds.jose.JOSEException;
import com.security.jwt.service.IJwtValidationService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.text.ParseException;

import java.io.IOException;

/**
 * JWT token validation filter that validates JWT token  and loads claims data to the security context
 *
 * @author Vasil Nakov
 */
@Component
@RequiredArgsConstructor
public class JwtTokenValidationFilter extends OncePerRequestFilter {

    private final IJwtValidationService jwtValidationService;

    /**
     * Adds JWT filter to the Spring Security filter chain
     *
     * @param request     the request
     * @param response    the response
     * @param filterChain the filter chain
     * @throws ServletException ServletException - default error
     * @throws IOException      IOException - default error
     */
    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request, @NonNull HttpServletResponse response, @NonNull FilterChain filterChain) throws ServletException, IOException {
        String token = extractToken(request);
        if (token != null) {
            try {
                jwtValidationService.validateToken(token);
            } catch (ParseException | JOSEException e) {
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                return;
            }
        } else {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            return;
        }
        filterChain.doFilter(request, response);
    }

    /**
     * Loads token form the {@link HttpServletRequest} header "x-secret-token"
     *
     * @param request the request
     * @return String extracted token
     */
    private String extractToken(HttpServletRequest request) {
        String token = request.getHeader("x-secret-token");
        if (token != null && token.startsWith("Bearer ")) {
            token = token.substring(7);
        }
        return token;
    }

}
