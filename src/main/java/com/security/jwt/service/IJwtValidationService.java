package com.security.jwt.service;

import com.nimbusds.jose.JOSEException;

import java.text.ParseException;

/**
 * JWT validation service interface defining the possible actions
 *
 * @author Vasil
 */
public interface IJwtValidationService {

    /**
     * validate the received token and add the data to the spring security context¶
     *
     * @param token the token
     * @throws ParseException ParseException
     * @throws JOSEException  JOSEException
     */
    void validateToken(String token) throws ParseException, JOSEException;
}
