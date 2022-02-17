package com.lunasphere.testee.auth;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;

import java.util.Date;
import java.util.concurrent.TimeUnit;

public abstract class JwtUtil {
    private static final String JWT_SECRET = System.getProperty("JWT_SECRET", "HelloWorld");

    public static String generate() {
        Algorithm algorithm = Algorithm.HMAC256(JWT_SECRET);

        Long expireTime = (new Date().getTime()) + TimeUnit.MINUTES.toMillis(5);

        return JWT.create()
                .withIssuer("localhost")
                .withSubject("admiral-leila")
                .withClaim("auth", "ADMIN")
                .withExpiresAt(new Date(expireTime))
                .sign(algorithm);
    }

    public static JwtContext decode(String token) throws JWTVerificationException {
        Algorithm algorithm = Algorithm.HMAC256(JWT_SECRET);

        JWTVerifier verifier = JWT.require(algorithm)
                .withIssuer("localhost").build();

        DecodedJWT jwt = verifier.verify(token);

        return new JwtContext(
                jwt.getSubject(),
                jwt.getClaim("auth").asString()
        );
    }
}
