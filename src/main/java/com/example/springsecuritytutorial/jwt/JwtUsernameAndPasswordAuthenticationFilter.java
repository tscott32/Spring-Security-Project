package com.example.springsecuritytutorial.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.LocalDate;
import java.util.Date;

// This class is responsible for verifying user credentials
public class JwtUsernameAndPasswordAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;

    public JwtUsernameAndPasswordAuthenticationFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    // Takes in the request and sends a response
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request,
                                                HttpServletResponse response) throws AuthenticationException {
        // Checks to see if the username and password are correct
        try {
            UsernameAndPasswordAuthenticationRequest authenticationRequest = new ObjectMapper()
                    .readValue(request.getInputStream(), UsernameAndPasswordAuthenticationRequest.class);

            // Create an Authentication object with the users username and password
            Authentication authentication = new UsernamePasswordAuthenticationToken(
                    authenticationRequest.getUsername(),
                    authenticationRequest.getPassword()
            );
            // Return an Authentication if can verify valid principal, AuthenticationException if invalid, or null if unknown
            Authentication authenticate = authenticationManager.authenticate(authentication);
            return authenticate;

        } catch(IOException e) {
            throw new RuntimeException(e);
        }
    }

    // Generates token and attaches to response upon successful authentication of user
    @Override
    protected void successfulAuthentication(HttpServletRequest request,
                                            HttpServletResponse response,
                                            FilterChain chain,
                                            Authentication authResult) throws IOException, ServletException {
        // Example of a secure key
        String secureKey = "ThisIsAnExampleOfAKeyButItIsNotVeryStrong";
        // Create the token itself
        String token = Jwts.builder() // Returns new JwtBuilder instance that can be configured and used to create JWT compact serialized strings
                .setSubject(authResult.getName())
                .claim("authorities", authResult.getAuthorities())
                .setIssuedAt(new Date())
                .setExpiration(java.sql.Date.valueOf(LocalDate.now().plusWeeks(2)))
                .signWith(Keys.hmacShaKeyFor(secureKey.getBytes()))
                .compact();

        // Add the token to the authorization header
        response.addHeader("Authorization", "Bearer " + token);

        super.successfulAuthentication(request, response, chain, authResult);
    }
}
