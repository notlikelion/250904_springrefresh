package com.example.springrefresh.filter;

import com.example.springrefresh.util.JwtUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

@RequiredArgsConstructor // jwtUtil 생성자
public class JwtFilter extends OncePerRequestFilter {
    private final JwtUtil jwtUtil;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        // 1. 헤더에서 토큰을 추출
        String authorization = request.getHeader("Authorization");
        System.out.println("authorization = " + authorization);
        // 2. 토큰이 있는지 찾아서 확인
//        if (StringUtils.hasText(authorization))
//        if (authorization.isBlank())
        if (authorization == null || !authorization.startsWith("Bearer ")) {
            filterChain.doFilter(request, response); // 보안 설정이 안된 상태에서 다음 필터로 가므로 튕김
            return;
        }
        // 3. 스킴을 체크 (Bearer)
//        String accessToken = authorization.substring(7);
        // authorization -> substring(5) rization, [5]부터 포함하는...
        String accessToken = authorization.substring("Bearer ".length());
        System.out.println("accessToken = " + accessToken);
        // 4. 만료 여부 확인
        if (jwtUtil.isExpired(accessToken)) {
            filterChain.doFilter(request, response);
            return;
        }
        // 5. 토큰에서 정보 추출 (username, role)
        String username = jwtUtil.getUsername(accessToken);
        String role = jwtUtil.getRole(accessToken);
        // 6. UserDetails를 생성
        User user = new User(username, "", List.of(new SimpleGrantedAuthority("ROLE_" + role))); // SGA
        // 7. SecurityContext -> Spring Security 관리 Context에 설정
        Authentication authToken = new UsernamePasswordAuthenticationToken(user, null, user.getAuthorities()); // UPAT
        // SCH
        SecurityContextHolder.getContext().setAuthentication(authToken);
        // 다음 필터 순서 실행
        filterChain.doFilter(request, response);
    }
}
