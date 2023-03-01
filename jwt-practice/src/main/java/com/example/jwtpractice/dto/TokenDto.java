package com.example.jwtpractice.dto;

import lombok.*;

import java.lang.ref.PhantomReference;

@Getter
@Setter
@Builder
@AllArgsConstructor
@NoArgsConstructor
// Token 정보를 Response할 때 사용하기 위함
public class TokenDto {

    private String grantType; // JWT에 대한 인증 타입. Bearer 사용
    private String accessToken;
    private String refreshToken;

}
