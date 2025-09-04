package com.example.springrefresh.controller;

import com.example.springrefresh.RefreshTokenRepository;
import com.example.springrefresh.util.JwtUtil;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequiredArgsConstructor
public class AuthController {
    private final AuthenticationManager authenticationManager;
    private final RefreshTokenRepository refreshTokenRepository;
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
        refreshTokenRepository.save(username, refreshToken);

        // 쿠키에 담아주는 과정
        response.addCookie(createCookie("refreshToken", refreshToken));
        // JSON 바디에 AccessToken Return
        // List.of(e1, e2, e3...) Map.of(k1, v1, k2, v2, ...)
        return ResponseEntity.ok(Map.of("accessToken", accessToken));
    }

    @Value("${jwt.refresh-token-expiration}")
    private Long refreshExpirationMs; // 필드 주입

    // HttpOnly
    private Cookie createCookie(String key, String value) {
        Cookie cookie = new Cookie(key, value);
//        cookie.setMaxAge(60 * 60 * 24 * 7); // refresh token
//        cookie.setMaxAge(60 * 5); // refresh token
        cookie.setMaxAge((int) (refreshExpirationMs / 1000)); // refresh token
        cookie.setHttpOnly(true); // 보안 설정
        cookie.setPath("/");
//        cookie.setSecure(true); // HTTPS -> 뒤에 배포까지 전제한 실습에서는 적용.
        return cookie;
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

        String savedToken = refreshTokenRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("서버에 저장되지 않은 토큰"));
        if (!savedToken.equals(refreshToken)) {
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
        refreshTokenRepository.save(username, newRefreshToken);

        // 쿠키에 담아주는 과정
        response.addCookie(createCookie("refreshToken", newRefreshToken));
        // JSON 바디에 AccessToken Return
        // List.of(e1, e2, e3...) Map.of(k1, v1, k2, v2, ...)
        return ResponseEntity.ok(Map.of("accessToken", newAccessToken));
    }
}
