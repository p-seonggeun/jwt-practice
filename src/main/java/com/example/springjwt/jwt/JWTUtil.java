package com.example.springjwt.jwt;

import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Date;

@Component
public class JWTUtil {

    private final SecretKey secretKey;

    // 미리 지정해둔 secret을 가지고 HS256 알고리즘을 통해
    // JWT에서 사용할 secretKey로 변환
    public JWTUtil(@Value("${spring.jwt.secret}") String secret) {
        this.secretKey = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), Jwts.SIG.HS256.key().build().getAlgorithm());
    }

    public String getUsername(String token) {
        // 암호환 된 토큰을 토큰이 우리 서버에서 생성된건지, 우리 서버에서 가지고 있는 키를 가지고 있는지
        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().get("username", String.class);
    }

    public String getRole(String token) {
        // 암호환 된 토큰을 토큰이 우리 서버에서 생성된건지, 우리 서버에서 가지고 있는 키를 가지고 있는지
        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().get("role", String.class);
    }

    public Boolean isExpired(String token) {
        // 토큰이 소멸되었는지, 내부 클레임에서 내부의 현재 시간값을 넣어주면 시간 값 확인가능 ?
        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().getExpiration().before(new Date());
    }

    public String createJwt(String username, String role, Long expiredMs) {
        return Jwts.builder()
                // claim -> 정보의 한 조각, 특정 키에 대한 데이터
                .claim("username", username)
                .claim("role", role)
                .issuedAt(new Date(System.currentTimeMillis())) // 언제 발행 됐는지 : 현재 발행 시간
                .expiration(new Date(System.currentTimeMillis() + expiredMs)) // 언제 소멸 될건지 : 현재 발행 시간 + expiredMs
                .signWith(secretKey) // secretKey를 통해 암호화를 진행
                .compact(); // 토큰을 채우다
    }

}
