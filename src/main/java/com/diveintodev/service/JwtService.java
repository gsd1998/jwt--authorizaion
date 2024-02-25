package com.diveintodev.service;


import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {

    private static final String SECRET_KEY  = "rgq08acm8cbhKo6U+SZ4RD1t1SWls/dSZ7t2LtFOAqQ4slJOzsxiC1UTBJzMwKG8";
    private static final long access_expiration = 60000; // 1 minute
    private static final long refresh_expiration =  86400000; //1 day

    public String extractUserNameFromToken(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    private Date extractExpirationDateFromToken(String token){
        return extractClaim(token,Claims::getExpiration);
    }

    private <T> T extractClaim(String token, Function<Claims,T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    private Claims extractAllClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(getSignKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    private boolean isTokenExpired(String token){
        return extractExpirationDateFromToken(token).before(new Date());
    }

    public boolean isTokenValid(String token, UserDetails userDetails){
        String username = extractUserNameFromToken(token);
        if(username.equals(userDetails.getUsername()) && !isTokenExpired(token))
            return true;
        else
            return  false;
    }

    public String generateToken(String username) {
        Map<String,Object> claims = new HashMap<>();
        return createToken(claims,username,access_expiration);
    }

    public String generateRefreshToken(String username) {
        return createToken(new HashMap<>(),username,refresh_expiration);
    }

    private String createToken(Map<String, Object> claims, String username, long expirationDate) {
        return Jwts.builder()
                .setClaims(claims)
                .setSubject(username)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis()+expirationDate))
                .signWith(getSignKey(),SignatureAlgorithm.HS256)
                .compact();
    }

    private Key getSignKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }

}
