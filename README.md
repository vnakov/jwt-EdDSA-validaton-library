# JWTValidatior
This library provides JWT token validation using a public key obtained from a JWKS (JSON Web Key Set) endpoint. 
It integrates seamlessly with Spring Security to block requests with invalid tokens and extracts the "sub" claim from the token, 
making the user ID readily available for client applications.

## Installation
Include the library in your project by adding the dependency to your pom.xml:

## Configuration
Configure the JWKS endpoint URL in your application properties or YAML file:
jwt.validation.jwks-url={protocol}://{host}:{port}/realms/{your-realm}/protocol/openid-connect/certs

## Usage
Enable the library in your Spring Boot application by adding component scan to your main:
@ComponentScan(basePackages = {"com.security.jwt"})