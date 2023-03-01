package com.example.jwtpractice.config;

import com.example.jwtpractice.jwt.JwtAccessDeniedHandler;
import com.example.jwtpractice.jwt.JwtAuthenticationEntryPoint;
import com.example.jwtpractice.jwt.JwtFilter;
import com.example.jwtpractice.jwt.JwtSecurityConfig;
import com.example.jwtpractice.jwt.TokenProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.SecurityBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.WebSecurityConfigurer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * Spring Security 설정을 위한 클래스
 */
// 기본적인 웹 보안(Spring Security)을 활성화 하겠다.
@EnableWebSecurity
// Controller에서 특정 페이지에 특정 권한이 있는 유저만 접근을 허용할 경우 @PreAuthorize 어노테이션을 사용하는데,
// 해당 어노테이션에 대한 설정을 활성화시키는 어노테이션임. 필수는 아님
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig {

    private final TokenProvider tokenProvider;
    private final JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;
    private final JwtAccessDeniedHandler jwtAccessDeniedHandler;

    public SecurityConfig(TokenProvider tokenProvider,
                          JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint,
                          JwtAccessDeniedHandler jwtAccessDeniedHandler) {
        this.tokenProvider = tokenProvider;
        this.jwtAuthenticationEntryPoint = jwtAuthenticationEntryPoint;
        this.jwtAccessDeniedHandler = jwtAccessDeniedHandler;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }



    /**
     * WebSecurityConfigurerAdapter가 deprecated 되어서 기존처럼 상속 받아 사용할 수 없고
     * 대신 SecurityFilterChain을 Bean으로 등록해서 사용해야함
     */
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        return http
                .csrf().disable() //토큰 방식을 사용하기 때문에 csrf 설정을 disable 처리

                .exceptionHandling()
                .authenticationEntryPoint(jwtAuthenticationEntryPoint)
                .accessDeniedHandler(jwtAccessDeniedHandler)

                //h2-console을 위한 설정
                .and()
                .headers()
                .frameOptions()
                .sameOrigin()

                //세션을 사용하지 않기 때문에 세션 설정을 STATELESS로 설정
                .and()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)

                .and()
                .authorizeRequests() //HttpServletRequest를 사용하는 요청들에 대해 접근 제한을 설정하겠다.
                .antMatchers("/api/hello").permitAll() // /api/hello 요청에 대해선 인증없이 접근을 허용하겠다.
//                .antMatchers("/api/authenticate").permitAll() //로그인 API 요청
                .antMatchers("/api/signup").permitAll() //회원가입 API 요청
                .antMatchers("/api/login").permitAll() //로그인 API 요청
                .antMatchers("/api/refresh").permitAll() // Access 토큰 재발급을 위한 요청
                .anyRequest().authenticated() //나머지 요청들은 모두 인증을 받아야한다.

                .and()
                .addFilterBefore(new JwtFilter(tokenProvider), UsernamePasswordAuthenticationFilter.class)
//                .apply(new JwtSecurityConfig(tokenProvider)) // 위 코드로 변경
                .build();
    }

    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return (web) -> web
                            .ignoring()
                            .antMatchers("/h2-console/**"
                                        ,"/favicon.ico"
                            );
    }

}
