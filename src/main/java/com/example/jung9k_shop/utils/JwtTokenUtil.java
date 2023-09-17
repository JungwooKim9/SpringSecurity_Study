package com.example.jung9k_shop.utils;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

import java.security.Signature;
import java.util.Date;

public class JwtTokenUtil {
    public static String createToken(String userName, String key, long expireTImeMs) {
        Claims claims = Jwts.claims();  // 일종의 map
        claims.put("userName", userName);

        return Jwts.builder()
                .setClaims(claims)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + expireTImeMs))
                .signWith(SignatureAlgorithm.HS256, key)
                .compact()
                ;
    }
}
