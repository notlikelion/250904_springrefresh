package com.example.springrefresh.controller;

import com.example.springrefresh.RefreshTokenRepository;
import com.example.springrefresh.util.JwtUtil;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;
import java.util.concurrent.TimeUnit;

@RestController
@RequiredArgsConstructor
public class AuthController {
    private final AuthenticationManager authenticationManager;
//    private final RefreshTokenRepository refreshTokenRepository;
    private final RedisTemplate<String, String> redisTemplate;
    private final JwtUtil jwtUtil;

    public record LoginRequest(String username, String password) {}

    @PostMapping("/login")
    // "{accessToken: ~}"
    public ResponseEntity<Map<String, String>> login(@RequestBody LoginRequest loginRequest, HttpServletResponse response) {
        // 사용자 인증
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequest.username(), loginRequest.password()));
        // 인증 성공시 UserDetails
        UserDetails userDetails = (UserDetails) authentication.getPrincipal();
        String username = userDetails.getUsername();
        String role = userDetails.getAuthorities().iterator().next().getAuthority()
                .replace("ROLE_", "");
        // ROLE_USER -> JWT

        // 토큰 생성
        String accessToken = jwtUtil.createToken(username, role, "access");
        String refreshToken = jwtUtil.createToken(username, role, "refresh");

        // 리프레시 토큰 -> 서버 관리
//        refreshTokenRepository.save(username, refreshToken);
        redisTemplate.opsForValue().set(
                username, // key
                refreshToken, // value - 여기까지만 입력해도 되지만...
                refreshExpirationMs, // TTL
                TimeUnit.MILLISECONDS
        );

        // 쿠키에 담아주는 과정
        response.addHeader("Set-Cookie", createCookie("refreshToken", refreshToken).toString());
        // JSON 바디에 AccessToken Return
        // List.of(e1, e2, e3...) Map.of(k1, v1, k2, v2, ...)
        return ResponseEntity.ok(Map.of("accessToken", accessToken));
    }

    @Value("${jwt.refresh-token-expiration}")
    private Long refreshExpirationMs; // 필드 주입

    // HttpOnly 쿠키 생성 헬퍼 메소드
    // ResponseCookie, sameSite
    private ResponseCookie createCookie(String key, String value) {
        return ResponseCookie.from(key, value)
                .path("/")
                .maxAge(refreshExpirationMs / 1000)
                .httpOnly(true)
                .sameSite("None") // sameSite ... Cookie 정책 -> 10시에 다시 설명.
                .secure(true)
                .build();
    }

    // 토큰 재발급 API
    @PostMapping("/reissue")
    public ResponseEntity<Map<String, String>> reissue(@CookieValue("refreshToken") String refreshToken, HttpServletResponse response) {
        if (refreshToken == null || jwtUtil.isExpired(refreshToken)) {
            // 401 -> 재로그인해라...
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of(
                    "error", "리프레시 토큰 만료"
            ));
        }
        String username = jwtUtil.getUsername(refreshToken);
        String role = jwtUtil.getRole(refreshToken);

//        String savedToken = refreshTokenRepository.findByUsername(username)
//                .orElseThrow(() -> new RuntimeException("서버에 저장되지 않은 토큰"));
        String savedToken = redisTemplate.opsForValue().get(username);
        if (!StringUtils.hasText(savedToken)) {
//        if (!savedToken.equals(refreshToken)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of(
                    "error", "토큰 불일치"
            ));
            // 내가 로그인을 하고 다른 곳에서도 로그인해서 A 브라우저 저장된 refresh 토큰이랑 B 브라우저(휴대폰?)에 저장된 토큰이 다른 것.
            // 중복 로그인 방지 로직 중에 하나
        }

        // 검증까지 되었다...
        // 토큰 생성
        String newAccessToken = jwtUtil.createToken(username, role, "access");
        String newRefreshToken = jwtUtil.createToken(username, role, "refresh");

        // 리프레시 토큰 -> 서버 관리
//        refreshTokenRepository.save(username, newRefreshToken);
        redisTemplate.opsForValue().set(
                username, // key
                newRefreshToken, // value - 여기까지만 입력해도 되지만...
                refreshExpirationMs, // TTL
                TimeUnit.MILLISECONDS
        );

        // 쿠키에 담아주는 과정
        response.addHeader("Set-Cookie", createCookie("refreshToken", newRefreshToken).toString());
        // JSON 바디에 AccessToken Return
        // List.of(e1, e2, e3...) Map.of(k1, v1, k2, v2, ...)
        return ResponseEntity.ok(Map.of("accessToken", newAccessToken));
    }
}