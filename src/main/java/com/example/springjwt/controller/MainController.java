package com.example.springjwt.controller;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Collection;
import java.util.Iterator;

@RestController
public class MainController {

    @GetMapping("/")
    public String mainP() {

        // username 추출
        String username = SecurityContextHolder.getContext().getAuthentication().getName();

        // role 추출
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        Iterator<? extends GrantedAuthority> iter = authorities.iterator();
        GrantedAuthority auth = iter.next();
        String role = auth.getAuthority();

        // STATELESS로 관리되긴 하지만 일시적인 요청에 대해서는 세션을 잠시동안 생성하기 때문에
        // 내부 시큐리티 컨텍스트 홀더에서 사용자 정보를 꺼낼 수 있다.
        return "Main Controller" + username + role;
    }
}
