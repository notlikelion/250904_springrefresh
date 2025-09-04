package com.example.springrefresh.controller;

import com.example.springrefresh.RefreshTokenRepository;
import com.example.springrefresh.util.JwtUtil;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
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
}
