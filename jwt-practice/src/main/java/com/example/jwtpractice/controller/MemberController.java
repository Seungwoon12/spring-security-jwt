package com.example.jwtpractice.controller;

import com.example.jwtpractice.dto.LoginDto;
import com.example.jwtpractice.dto.MemberDto;
import com.example.jwtpractice.dto.TokenDto;
import com.example.jwtpractice.jwt.TokenProvider;
import com.example.jwtpractice.service.MemberService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;
import java.net.http.HttpResponse;

@RestController
@Slf4j
@RequestMapping("/api")
public class MemberController {

    private final MemberService memberService;
    private final TokenProvider tokenProvider;

    public MemberController(MemberService memberService, TokenProvider tokenProvider) {
        this.memberService = memberService;
        this.tokenProvider = tokenProvider;
    }

    @PostMapping("/signup")
    public ResponseEntity<MemberDto> signup(@Valid @RequestBody MemberDto memberDto) {
        return ResponseEntity.ok(memberService.signup(memberDto));
    }

    //    @ResponseBody
    @PostMapping("/login")
    public ResponseEntity<TokenDto> login(@Valid @RequestBody LoginDto loginDto) {
        log.info("로그인 로직 수행");
        return ResponseEntity.ok(memberService.login(loginDto));
    }


    @GetMapping("/user")
    @PreAuthorize("hasAnyRole('USER', 'ADMIN')")
    public ResponseEntity<MemberDto> getMyUserInfo() {
        return ResponseEntity.ok(memberService.getMyMemberWithAuthorities());
    }

    @GetMapping("/user/{username}")
    @PreAuthorize("hasAnyRole('ADMIN')")
    public ResponseEntity<MemberDto> getUserInfo(@PathVariable String username) {
        return ResponseEntity.ok(memberService.getMemberWithAuthorities(username));
    }


    @GetMapping("/refresh")
    public ResponseEntity<TokenDto> recreateToken(HttpServletRequest request) {
        String refreshToken = request.getHeader("Refresh-Token");

        // refresh 토큰이 유효하다면 access 토큰 재발급
        if (tokenProvider.validateRefreshToken(refreshToken)) {
            TokenDto tokenDto = memberService.recreateToken(refreshToken);
            return ResponseEntity.ok(tokenDto);
        } else {
            log.info("refresh 토큰이 만료되었으므로 재로그인이 필요함");
        }

        return new ResponseEntity<>(null, HttpStatus.BAD_REQUEST);
    }
}
