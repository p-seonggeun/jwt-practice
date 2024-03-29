package com.example.springjwt.jwt;


import com.example.springjwt.dto.CustomUserDetails;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.util.Collection;
import java.util.Iterator;

/**
 * UsernamePasswordAuthenticationFilter를 커스텀 (FormLogin 방식을 disable 시켰기 때문에 기존 필터가 동작하지 않아서)
 * Filter에 요청이 오면 attemptAuthentication 메서드가 호출되고
 * request에서 username, password를 추출한뒤에 UsernamePasswordAuthenticationToken(DTO 역할)로 변환
 * 변환한 후 검증을 위해 AuthenticationManager로 전달하면 AuthenticationManager에서 검증을 진행
 * 검증 방법은 DB에서 회원정보를 땡겨온뒤 UserDetailsService를 통해 정보를 받고 검증
 */
@RequiredArgsConstructor
public class LoginFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;
    private final JWTUtil jwtUtil;

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)  throws AuthenticationException {
        // 클라이언트 요청에서 username, password 추출
        String username = obtainUsername(request);
        String password = obtainPassword(request);

        // 스프링 시큐리티에서 username과 password를 검증하기 위해서는 token에 담아야함
        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(username, password, null);

        // token에 담은 검증을 위한 AuthenticationManager로 전달
        return authenticationManager.authenticate(authToken);
    }

    // 로그인 성공시 실행하는 메서드 (여기서 JWT를 발급하면 됨)
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authentication) {
        // 특정한 유저를 확인 할 수 있음
        CustomUserDetails customUserDetails = (CustomUserDetails) authentication.getPrincipal();
        // username 추출
        String username = customUserDetails.getUsername();
        // role 추출
        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        Iterator<? extends GrantedAuthority> iterator = authorities.iterator();
        GrantedAuthority auth = iterator.next();
        String role = auth.getAuthority();

        // jwtUtil에 토큰 생성을 요청함
        String token = jwtUtil.createJwt(username, role, 60*60*10L);

        // key 값 : Authorization
        // 인증방식 : Bearer
        // 띄어쓰기 인증토큰
        // RFC 7235 정의에 따라 Authorizaiton: 타입 인증토큰
        response.addHeader("Authorization", "Bearer " + token);
    }

    // 로그인 실패시 실행하는 메서드

    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) {
        response.setStatus(401);
    }
}
