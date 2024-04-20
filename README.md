# JWTValidatior
This library provides EdDSA signed JWT token validation using a public key obtained from a JWKS (JSON Web Key Set) endpoint. 
It integrates seamlessly with Spring Security to block requests with invalid tokens and extracts the "sub" claim from the token, 
making the user ID readily available for client applications.

## Installation
Download and build the project.
Include the library in your project by adding the dependency to your pom.xml, example:
        <dependency>
            <groupId>com.security</groupId>
            <artifactId>jwt</artifactId>
            <version>0.0.1-SNAPSHOT</version>
        </dependency>

## Configuration
Configure the JWKS endpoint URL in your application properties or YAML file:
jwt.validation.jwks-url={protocol}://{host}:{port}/realms/{your-realm}/protocol/openid-connect/certs

## Usage
Enable the library in your Spring Boot application by adding component to your main method:
@ComponentScan(basePackages = {"com.security.jwt"})
Then you can retrieve the "sub" from the JWT token by using @AuthenticationPrincipal String userId in your controller method signature, example:
@RestController
public class UserController {
    @GetMapping("/user")
    public String getUserInfo(@AuthenticationPrincipal String userId) {
        return "User ID: " + userId;
    }
}
