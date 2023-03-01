package com.example.jwtpractice.service;

import com.example.jwtpractice.entity.Member;
import com.example.jwtpractice.repository.MemberRepository;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.stream.Collectors;

@Component("userDetailsService")
public class CustomUserDetailsService implements UserDetailsService {

    private final MemberRepository memberRepository;

    public CustomUserDetailsService(MemberRepository  memberRepository) {
        this.memberRepository = memberRepository;
    }

    @Override
    @Transactional
    public UserDetails loadUserByUsername(String memberName) throws UsernameNotFoundException {
        return memberRepository.findOneWithAuthoritiesByMemberName(memberName)
                .map(member -> createUserDetails(memberName, member))
                .orElseThrow(() -> new UsernameNotFoundException(memberName + " -> 해당 유저는 회원가입 되어 있지 않습니다."));
    }

    private org.springframework.security.core.userdetails.User createUserDetails(String memberName, Member member) {
        if (!member.isActivated()) {
            throw new RuntimeException(memberName + " -> 해당 유저는 활성화되어 있지 않습니다.");
        }
        List<GrantedAuthority> grantedAuthorities = member.getAuthorities().stream()
                .map(authority -> new SimpleGrantedAuthority(authority.getAuthorityName()))
                .collect(Collectors.toList());

        return new org.springframework.security.core.userdetails.User(
                member.getMemberName(),
                member.getPassword(),
                grantedAuthorities);
    }
}
