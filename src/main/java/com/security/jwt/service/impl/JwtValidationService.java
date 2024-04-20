package com.security.jwt.service.impl;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.Ed25519Verifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jwt.SignedJWT;
import com.security.jwt.service.IJwtValidationService;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.beans.factory.annotation.Value;

import java.net.URI;
import java.net.URL;
import java.text.ParseException;

/**
 * JWT validation service interface defining the possible actions
 *
 * @author Vasil
 */
@Service
public class JwtValidationService implements IJwtValidationService {

    @Value("${jwt.validation.jwks-url}")
    private String jwksURL;


    /**
     * Validates the received token and saves the Authorization in the {@link SecurityContextHolder}
     *
     * @param token the token to validate and extract claims from
     * @throws ParseException ParseException
     * @throws JOSEException  JOSEException
     */
    @Override
    public void validateToken(String token) throws ParseException, JOSEException {
        SignedJWT jwt = SignedJWT.parse(token);
        JWSHeader header = jwt.getHeader();
        String algorithm = header.getAlgorithm().getName();

        // Retrieve the key ID (kid) from the JWT header
        String kid = header.getKeyID();

        // Retrieve the public key from the JWK endpoint based on the key ID
        JWK publicKey = getPublicKeyFromJWKS(kid);

        // Create a JWS verifier based on the public key
        JWSVerifier verifier;
        if (publicKey != null && algorithm.equals("EdDSA")) {
            verifier = new Ed25519Verifier((OctetKeyPair) publicKey);
        } else {
            throw new JOSEException("Invalid JWT algorithm: " + algorithm);
        }

        // Verify token and add info to the security context
        if (jwt.verify(verifier)) {
            Authentication authentication = new UsernamePasswordAuthenticationToken(jwt.getJWTClaimsSet().getSubject(), null);
            SecurityContextHolder.getContext().setAuthentication(authentication);
        } else {
            throw new JOSEException("Invalid JWT token");
        }
    }

    /**
     * Loads the public key using the defined in the configurations file URL if possible
     *
     * @param kid the key id
     * @return JWK get public key fromJWKS or null if teh URL is not available or an error occurs
     */
    private JWK getPublicKeyFromJWKS(String kid) {
        JWK jwk = null;
        try {
            URL url = new URI(jwksURL).toURL();
            JWKSet jwkSet = JWKSet.load(url);
            jwk = jwkSet.getKeyByKeyId(kid);
        } catch (Exception ignored) {
        }
        return jwk;
    }
}
