package com.example.jwtpractice.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;

import javax.swing.text.html.Option;
import java.util.Optional;

public class SecurityUtil {

    private static final Logger log = LoggerFactory.getLogger(SecurityUtil.class);

    private SecurityUtil() {
    }

    public static Optional<String> getCurrentMemberName() {
        final Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication == null) {
            log.debug("Security Context에 인증 정보가 없습니다.");
            return Optional.empty();
        }

        String memberName = null;
        if (authentication.getPrincipal() instanceof UserDetails) {
            UserDetails springSecurityUser = (UserDetails) authentication.getPrincipal();
            memberName = springSecurityUser.getUsername();
        } else if (authentication.getPrincipal() instanceof String) {
            memberName = (String) authentication.getPrincipal();
        }

        return Optional.ofNullable(memberName);
    }
}
