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

    //???????????? ????????? ??????
    @Transactional
    public MemberDto signup(MemberDto memberDto) {
        if (memberRepository.findOneWithAuthoritiesByMemberName(memberDto.getMemberName()).orElse(null) != null) {
            throw new RuntimeException("?????? ???????????? ?????? ???????????????.");
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


    // ????????? ????????? ??????
    @Transactional
    public TokenDto login(LoginDto loginDto) {
        // ???????????? ????????? ????????? ID/PW??? ???????????? Authentication ?????? ??????.
        // ??? ??? Authentication??? ?????? ????????? ???????????? authenticated ?????? false ?????????.
        UsernamePasswordAuthenticationToken authenticationToken =
                new UsernamePasswordAuthenticationToken(loginDto.getMemberName(), loginDto.getPassword());

        // ?????? ??????(????????? ???????????? ??????)??? ??????????????? ??????
        // authenticate ???????????? ????????? ??? CustomUserDetailsService?????? ?????? loadUserByUsername ???????????? ??????
        Authentication authentication = authenticationManagerBuilder.getObject().authenticate(authenticationToken);


        // ?????? ????????? ???????????? JWT ??????
        return tokenProvider.createToken(authentication);
    }



    // memberName??? ???????????? ?????? ??????
    @Transactional(readOnly = true)
    public MemberDto getMemberWithAuthorities(String memberName) {
        return MemberDto.from(memberRepository.findOneWithAuthoritiesByMemberName(memberName).orElse(null));
    }

    // ?????? SecurityContext??? ????????? memberName ????????? ?????????
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
                .orElseThrow(() -> new RuntimeException("DB??? ?????? refresh ?????? ????????? ????????????."));

        String memberName = refresh.getMemberName();
        Member member = memberRepository.findOneWithAuthoritiesByMemberName(memberName)
                .orElseThrow(() -> new NotFoundMemberException(memberName + " -> ?????? ????????? ???????????? ????????????."));

        String newAccessToken = tokenProvider.recreateAccessToken(member);

       return TokenDto.builder()
                .grantType("Bearer")
                .accessToken(newAccessToken)
                .refreshToken(refreshToken)
                .build();

    }
}
