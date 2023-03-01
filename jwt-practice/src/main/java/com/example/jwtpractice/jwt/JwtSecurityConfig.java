package com.example.jwtpractice.jwt;

import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

//  SecurityConfig에 직접 추가로 변경
public class JwtSecurityConfig extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity> {
//
//    private TokenProvider tokenProvider;
//
//    public JwtSecurityConfig(TokenProvider tokenProvider) {
//        this.tokenProvider = tokenProvider;
//    }
//
//    @Override
//    public void configure(HttpSecurity httpSecurity) {
//        JwtFilter customFilter = new JwtFilter(tokenProvider);
//        httpSecurity.addFilterBefore(customFilter, UsernamePasswordAuthenticationFilter.class);
//    }
//
}
