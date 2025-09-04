package com.example.springrefresh.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;

@Component // 의존성 주입 -> 컨테이너 등록
public class JwtUtil {
    // @Value 때문에 직접 생성자를 작성하거나, 필드 주입
    private final SecretKey secretKey;
    private final Long accessExpirationMs; // Access Token의 만료일시
    private final Long refreshExpirationMs; // Refresh Token의 만료일시

    // 자동으로 생성이 되어서 컨테이너에 등록
    public JwtUtil(
            // {jwt.secret} -> applcation.yml과 호응
            @Value("${jwt.secret}") String secret,
            @Value("${jwt.access-token-expiration}") Long accessExpirationMs,
            @Value("${jwt.refresh-token-expiration}") Long refreshExpirationMs
    ) {
//        this.secretKey = new SecretKeySpec(secret.getBytes(), "HmacSHA256");
        // soutv -> 방향키 위 아래로
        System.out.println("secret = " + secret);
        System.out.println("accessExpirationMs = " + accessExpirationMs);
        System.out.println("refreshExpirationMs = " + refreshExpirationMs);
        this.secretKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8)); // 텍스트 -> 바이트 => 암호화된 인코딩으로 바꿔서 JWT에 쓸 수 있게 하겠다
        this.accessExpirationMs = accessExpirationMs;
        this.refreshExpirationMs = refreshExpirationMs;
    };

//    public String createToken(String username, String role, boolean isRefreshToken) {
//    public String createToken(String username, String role, boolean isAccessToken) {
    public String createToken(String username, String role, String type) {
        Date now = new Date();
        // 만료일시가 분기가 되어야 한다
        Long expiration = type.equals("access") ? accessExpirationMs : refreshExpirationMs; // access -> 짧은 걸 주고, 아니면 긴 걸 준다
        Date expiryDate = new Date(now.getTime() + expiration);
        return Jwts.builder()
                .subject(username) // 로그인 정보
                // claim
                .claim("username", username)
                .claim("role", role)
                .issuedAt(now) // 발행일시
                .expiration(expiryDate) // 만료일시
                .signWith(secretKey) // 암호화
                .compact();
    }

//    public String createAccessToken(String username) {
//        Date now = new Date();
//        Date expiryDate = new Date(now.getTime() + accessExpirationMs);
//        return Jwts.builder()
//                .subject(username) // 로그인 정보
//                .issuedAt(now) // 발행일시
//                .expiration(expiryDate) // 만료일시
//                .signWith(secretKey) // 암호화
//                .compact();
//    }

    public Claims getClaims(String token) {
        return Jwts.parser().verifyWith(secretKey)
                .build().parseSignedClaims(token).getPayload();
    }

    // 토큰에서 사용자 이름 추출
    public String getUsername(String token) {
//        return getClaims(token).getSubject(); // subject -> username
        return getClaims(token).get("username", String.class);
        // .claim("username", username)
    }

    // 토큰에서 역할 추출
    public String getRole(String token) {
//        return getClaims(token).getSubject(); // subject -> username
        return getClaims(token).get("role", String.class);
        // .claim("role", role)
    }
}
