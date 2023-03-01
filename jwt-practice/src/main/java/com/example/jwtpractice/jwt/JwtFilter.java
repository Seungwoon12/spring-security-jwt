package com.example.jwtpractice.jwt;

import com.example.jwtpractice.dto.TokenDto;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

/**
 * 클라이언트 요청 시 JWT 인증을 하기 위해 만든 커스텀 필터
 * UsernamePasswordAuthenticationFilter 이전에 실행됨
 * 즉, Username + Password를 통한 인증을 Jwt를 통해 수행하겠다.
 */

public class JwtFilter extends GenericFilterBean {

    private static final Logger log = LoggerFactory.getLogger(JwtFilter.class);

    public static final String AUTHORIZATION_HEADER = "Authorization";

    private final TokenProvider tokenProvider;

    public JwtFilter(TokenProvider tokenProvider) {
        this.tokenProvider = tokenProvider;
    }

    //jwt 토큰의 인증정보를 현재 실행중인 SecurityContext에 저장하는 역할 수행
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest httpServletRequest = (HttpServletRequest) request;
        // Request Header에서 Access 토큰 추출
        TokenDto token = resolveToken(httpServletRequest);
        String requestURI = httpServletRequest.getRequestURI();

        // validateToken 메소드로 access 토큰의 유효성을 검사
        if (StringUtils.hasText(token.getAccessToken()) && tokenProvider.validateAccessToken(token)) {
            // 토큰이 유효할 경우 토큰에서 Authentication 객체를 가져와서 SecurityContext에 저장
            Authentication authentication = tokenProvider.getAuthentication(token.getAccessToken());
            SecurityContextHolder.getContext().setAuthentication(authentication);
            log.debug("Security Context에 '{}' 인증 정보를 저장했습니다, uri: {}", authentication.getName(), requestURI);
        } else {
            log.debug("유효한 JWT 토큰이 없습니다, url: {}", requestURI);
        }
        chain.doFilter(request, response);
    }

    // Request Header에서 access 토큰과 refresh 토큰을 꺼내오기 위한 메소드
    private TokenDto resolveToken(HttpServletRequest request) {
        String accessToken = request.getHeader(AUTHORIZATION_HEADER);
        String refreshToken = request.getHeader("Refresh-Token");


        if (StringUtils.hasText(accessToken) && accessToken.startsWith("Bearer")) {
            accessToken = accessToken.substring(7); // JWT는 Bearer E2FAS~~ 이런식으로 앞에 Bearer 이 붙음
        }

        log.info("access Token = {}", accessToken);
        log.info("refresh Token = {}", refreshToken);

        return TokenDto.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .build();
    }
}
