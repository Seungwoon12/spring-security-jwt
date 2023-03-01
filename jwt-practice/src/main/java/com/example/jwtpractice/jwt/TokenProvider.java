package com.example.jwtpractice.jwt;

import com.example.jwtpractice.dto.TokenDto;
import com.example.jwtpractice.entity.Authority;
import com.example.jwtpractice.entity.Member;
import com.example.jwtpractice.entity.RefreshToken;
import com.example.jwtpractice.repository.RefreshTokenRepository;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.aspectj.apache.bcel.generic.RET;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.stream.Collectors;

/**
 * TokenProvider 클래스는 토큰의 생성, 토큰의 유효성 검증등을 담당함
 */
@Component
public class TokenProvider implements InitializingBean {

    private final Logger log = LoggerFactory.getLogger(TokenProvider.class);

    private final RefreshTokenRepository refreshTokenRepository;

    private static final String AUTHORITIES_KEY = "auth";

    private final String secret;
    private final long accessTokenValidityInMilliseconds;
    private final long refreshTokenValidityInMilliseconds;

    private Key key;

    public TokenProvider(
            @Value("${jwt.secret}") String secret,
            @Value("${jwt.accessToken-validity-in-seconds}") long accessTokenValidityInSeconds,
            @Value("${jwt.refreshToken-validity-in-seconds}") long refreshTokenValidityInSeconds,
            RefreshTokenRepository refreshTokenRepository) {
        this.secret = secret;
        this.accessTokenValidityInMilliseconds = accessTokenValidityInSeconds * 1000;
        this.refreshTokenValidityInMilliseconds = refreshTokenValidityInSeconds * 1000;
        this.refreshTokenRepository = refreshTokenRepository;
    }

    @Override
    public void afterPropertiesSet() throws Exception {
        byte[] keyBytes = Decoders.BASE64.decode(secret);
        this.key = Keys.hmacShaKeyFor(keyBytes);
    }

    /**
     *Authentication(유저 정보) 객체의 권한 정보를 이용해서 토큰을 생성하는 역할
     */
    public TokenDto createToken(Authentication authentication) {
        // 권한 가져오는 작업
        String authorities = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));

        long now = (new Date()).getTime();
        // Access Token 생성
        Date accessTokenExpiration = new Date(now + this.accessTokenValidityInMilliseconds);
        String accessToken = Jwts.builder()
                .setSubject(authentication.getName())
                .claim(AUTHORITIES_KEY, authorities)
                .signWith(key, SignatureAlgorithm.HS512)
                .setExpiration(accessTokenExpiration)
                .compact();

        // Refresh Token 생성
        Date refreshTokenExpiration = new Date(now + this.refreshTokenValidityInMilliseconds);
        String refreshToken = Jwts.builder()
                .setExpiration(refreshTokenExpiration)
                .signWith(key, SignatureAlgorithm.HS512)
                .compact();

        // Refresh Token을 DB에 저장
        RefreshToken refresh = RefreshToken.builder()
                .tokenValue(refreshToken)
                .memberName(authentication.getName())
                .build();
        // 요청한 권한 정보를 갖는 회원의 refresh 토큰이 DB에 이미 존재하면 삭제 후 새롭게 저장한다.
        if (refreshTokenRepository.existsByMemberName(authentication.getName())) {
            refreshTokenRepository.deleteByMemberName(authentication.getName());
            refreshTokenRepository.save(refresh);
        } else {
            refreshTokenRepository.save(refresh);
        }

        return TokenDto.builder()
                .grantType("Bearer")
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .build();
    }


    /**
     * JWT 토큰을 복호화. accessToken에 담겨있는 권한 정보를 이용해 Authentication 객체를 리턴하는 메소드
     */
    public Authentication getAuthentication(String accessToken) {
        // 토큰 복호화
        Claims claims = Jwts
                .parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(accessToken)
                .getBody();

        if (claims.get(AUTHORITIES_KEY) == null) {
            throw new RuntimeException("권한 정보가 없는 토큰입니다.");
        }

        // 클레임에서 권한 정보 가져오기
        Collection<? extends GrantedAuthority> authorities =
                Arrays.stream(claims.get(AUTHORITIES_KEY).toString().split(","))
                        .map(SimpleGrantedAuthority::new)
                        .collect(Collectors.toList());

        // User 객체를 만들어서 Authentication을 반환. User는 UserDetails 인터페이스를 구현
        User principal = new User(claims.getSubject(), "", authorities);
        // credential은 유저의 password를 의미하는듯?
        return new UsernamePasswordAuthenticationToken(principal, "", authorities);
    }


    /**
     * 토큰의 유효성 검증을 수행하는 validateToken 메소드
     */
    public boolean validateAccessToken(TokenDto token) {
        try {
            Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token.getAccessToken());
            return true;
        } catch (io.jsonwebtoken.security.SecurityException | MalformedJwtException e) {
            log.info("잘못된 JWT 서명입니다.");
        } catch (ExpiredJwtException e) {
            log.info("만료된 Access 토큰입니다.");

        } catch (UnsupportedJwtException e) {
            log.info("지원되지 않는 JWT 토큰입니다.");
        } catch (IllegalArgumentException e) {
            log.info("JWT 토큰이 잘못되었습니다.");
        }
        return false;
    }


    public boolean validateRefreshToken(String refreshToken) {

        try {
            // refreshToken 검증
            Jws<Claims> claims = Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(refreshToken);
            return true;

        } catch (io.jsonwebtoken.security.SecurityException | MalformedJwtException e) {
            log.info("잘못된 JWT 서명입니다.");
        } catch (ExpiredJwtException e) {
            log.info("만료된 refresh 토큰입니다.");
        } catch (UnsupportedJwtException e) {
            log.info("지원되지 않는 JWT 토큰입니다.");
        } catch (IllegalArgumentException e) {
            log.info("JWT 토큰이 잘못되었습니다.");
        }
        return false;
    }



    public String recreateAccessToken(Member member) {
//        Claims claims = Jwts.claims().setSubject(memberName);
//        claims.put("auth", auth);

        String authorities = member.getAuthorities().stream()
                .map(Authority::getAuthorityName)
                .collect(Collectors.joining(","));

        Date now = new Date();
        // Access 토큰 생성
        String accessToken = Jwts.builder()
                .setSubject(member.getMemberName())
                .claim(AUTHORITIES_KEY, authorities)
                .setIssuedAt(now) // 토큰 발행 시간 정보
                .setExpiration(new Date(now.getTime() + accessTokenValidityInMilliseconds))
                .signWith(key, SignatureAlgorithm.HS512)
                .compact();


        return accessToken;

    }


}
