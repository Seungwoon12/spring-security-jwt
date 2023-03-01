package com.example.jwtpractice.service;

import com.example.jwtpractice.dto.LoginDto;
import com.example.jwtpractice.dto.MemberDto;
import com.example.jwtpractice.dto.TokenDto;
import com.example.jwtpractice.entity.Authority;
import com.example.jwtpractice.entity.Member;
import com.example.jwtpractice.entity.RefreshToken;
import com.example.jwtpractice.exception.NotFoundMemberException;
import com.example.jwtpractice.jwt.TokenProvider;
import com.example.jwtpractice.repository.MemberRepository;
import com.example.jwtpractice.repository.RefreshTokenRepository;
import com.example.jwtpractice.util.SecurityUtil;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.RequestBody;

import java.util.Collections;


@Service
public class MemberService {

    private final MemberRepository memberRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManagerBuilder authenticationManagerBuilder;
    private final TokenProvider tokenProvider;
    private final RefreshTokenRepository refreshTokenRepository;

    public MemberService(MemberRepository memberRepository,
                         PasswordEncoder passwordEncoder,
                         AuthenticationManagerBuilder authenticationManagerBuilder,
                         TokenProvider tokenProvider,
                         RefreshTokenRepository refreshTokenRepository) {
        this.memberRepository = memberRepository;
        this.passwordEncoder = passwordEncoder;
        this.authenticationManagerBuilder = authenticationManagerBuilder;
        this.tokenProvider = tokenProvider;
        this.refreshTokenRepository = refreshTokenRepository;
    }

    //회원가입 로직을 수행
    @Transactional
    public MemberDto signup(MemberDto memberDto) {
        if (memberRepository.findOneWithAuthoritiesByMemberName(memberDto.getMemberName()).orElse(null) != null) {
            throw new RuntimeException("이미 가입되어 있는 유저입니다.");
        }

        Authority authority = Authority.builder()
                .authorityName("ROLE_USER")
                .build();

        Member member = Member.builder()
                .memberName(memberDto.getMemberName())
                .password(passwordEncoder.encode(memberDto.getPassword()))
                .nickname(memberDto.getNickname())
                .authorities(Collections.singleton(authority))
                .activated(true)
                .build();

        return MemberDto.from(memberRepository.save(member));

    }


    // 로그인 로직을 수행
    @Transactional
    public TokenDto login(LoginDto loginDto) {
        // 사용자가 로그인 요청한 ID/PW를 기반으로 Authentication 객체 생성.
        // 이 때 Authentication은 인증 여부를 확인하는 authenticated 값이 false 상태임.
        UsernamePasswordAuthenticationToken authenticationToken =
                new UsernamePasswordAuthenticationToken(loginDto.getMemberName(), loginDto.getPassword());

        // 실제 검증(사용자 비밀번호 체크)이 이루어지는 부분
        // authenticate 메서드가 실행될 때 CustomUserDetailsService에서 만든 loadUserByUsername 메서드가 실행
        Authentication authentication = authenticationManagerBuilder.getObject().authenticate(authenticationToken);


        // 인증 정보를 기반으로 JWT 생성
        return tokenProvider.createToken(authentication);
    }



    // memberName을 기준으로 정보 조회
    @Transactional(readOnly = true)
    public MemberDto getMemberWithAuthorities(String memberName) {
        return MemberDto.from(memberRepository.findOneWithAuthoritiesByMemberName(memberName).orElse(null));
    }

    // 현재 SecurityContext에 저장된 memberName 정보만 가져옴
    @Transactional(readOnly = true)
    public MemberDto getMyMemberWithAuthorities() {
        return MemberDto.from(SecurityUtil.getCurrentMemberName()
                .flatMap(memberRepository::findOneWithAuthoritiesByMemberName)
                .orElseThrow(() -> new NotFoundMemberException("Member not Found"))
        );
    }

    @Transactional
    public TokenDto recreateToken(String refreshToken) {
        RefreshToken refresh = refreshTokenRepository.findByTokenValue(refreshToken)
                .orElseThrow(() -> new RuntimeException("DB에 해당 refresh 토큰 정보가 없습니다."));

        String memberName = refresh.getMemberName();
        Member member = memberRepository.findOneWithAuthoritiesByMemberName(memberName)
                .orElseThrow(() -> new NotFoundMemberException(memberName + " -> 해당 맴버는 존재하지 않습니다."));

        String newAccessToken = tokenProvider.recreateAccessToken(member);

       return TokenDto.builder()
                .grantType("Bearer")
                .accessToken(newAccessToken)
                .refreshToken(refreshToken)
                .build();

    }
}
