package com.example.sso.shiro;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import lombok.extern.slf4j.Slf4j;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.credential.CredentialsMatcher;

@Slf4j
public class JWTCredentialsMatcher implements CredentialsMatcher {

    @Override
    public boolean doCredentialsMatch(AuthenticationToken token, AuthenticationInfo info) {
        String tokenStr = (String) token.getCredentials();
        Object stored = info.getCredentials();
        String salt = stored.toString();

        UserDto userDto = (UserDto) info.getPrincipals().getPrimaryPrincipal();
        try{
            Algorithm algorithm = Algorithm.HMAC256(salt);
            JWTVerifier verifier = JWT.require(algorithm)
                    .withClaim("username",userDto.getUsername())
                    .build();
            verifier.verify(tokenStr);
            return true;
        }catch (JWTVerificationException e){
            log.error("Token Error:{}", e.getMessage());
        }
        return false;
    }
}