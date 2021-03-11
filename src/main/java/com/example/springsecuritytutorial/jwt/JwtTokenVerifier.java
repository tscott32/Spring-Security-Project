package com.example.springsecuritytutorial.jwt;

import com.google.common.base.Strings;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.crypto.SecretKey;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

// Class to verify JWT token upon request of client
public class JwtTokenVerifier extends OncePerRequestFilter {

    private final SecretKey secretKey;
    private final JwtConfig jwtConfig;

    public JwtTokenVerifier(SecretKey secretKey,
                            JwtConfig jwtConfig) {
        this.secretKey = secretKey;
        this.jwtConfig = jwtConfig;
    }

    // Execute this filter for every request from the client to verify JWT
    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        // Get the token from the header
        String authorizationHeader = request.getHeader(jwtConfig.getAuthorizationHeader());

        // Check if the header starts with "Bearer " and if so, reject request because there is no way to authenticate
        if (Strings.isNullOrEmpty(authorizationHeader) || !authorizationHeader.startsWith(jwtConfig.getTokenPrefix())) {
            filterChain.doFilter(request, response);
            return;
        }

        // Remove "Bearer " from header so that we just have the token
        String token = authorizationHeader.replace(jwtConfig.getTokenPrefix(), "");

        // If the header is not empty and it does start with "Bearer "
        try {

            // Parses the token and key so we can extract data such as the body, issuedAt, issuer, etc
            Jws<Claims> claimsJws = Jwts.parser()
                    .setSigningKey(secretKey)
                    .parseClaimsJws(token);

            // Get the body or payload of the message
            Claims body = claimsJws.getBody();
            // Get the subject of the data which is the username
            String username = body.getSubject();
            // Get the authorities that the user has, which is a list of maps
            List<Map<String, String>> authorities = (List<Map<String, String>>) body.get("authorities");

            // Store the list of authorities in a set
            Set<SimpleGrantedAuthority> simpleGrantedAuthoritySet = authorities.stream()
                    .map(m -> new SimpleGrantedAuthority(m.get("authority")))
                    .collect(Collectors.toSet());

            // Create new Authentication object with client credentials
            Authentication authentication = new UsernamePasswordAuthenticationToken(
                    username,
                    null,
                    simpleGrantedAuthoritySet
            );

            // Client that sent token is verified
            SecurityContextHolder.getContext().setAuthentication(authentication);

        } catch (JwtException e) {
            throw new IllegalStateException(String.format("Token %s cannot be trusted", token));
        }

        // This makes sure that the initial request and response on this filter is passed down to the next filter in the chain
        filterChain.doFilter(request, response);
    }
}
