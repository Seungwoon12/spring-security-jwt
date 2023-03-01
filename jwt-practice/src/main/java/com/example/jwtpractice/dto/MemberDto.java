package com.example.jwtpractice.dto;

import com.example.jwtpractice.entity.Member;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.*;

import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;
import java.util.Set;
import java.util.stream.Collectors;

@Getter
@Setter
@Builder
@AllArgsConstructor
@NoArgsConstructor
//회원가입시에 사용하기 위함
public class MemberDto {

    @NotNull
    @Size(min = 3, max = 50)
    private String memberName;

    // 쓰려는 경우(deserialize)에만 접근 허용. 요청할 때만 사용되고 응답 결과를 만들 때는 해당 필드를 제외
    @JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
    @NotNull
    @Size(min = 3, max = 100)
    private String password;

    @NotNull
    @Size(min = 3, max = 50)
    private String nickname;

    private Set<AuthorityDto> authorityDtoSet;

    public static MemberDto from(Member member) {
        if (member == null) return null;

        return MemberDto.builder()
                .memberName(member.getMemberName())
                .nickname(member.getNickname())
                .authorityDtoSet(member.getAuthorities().stream()
                        .map(authority -> AuthorityDto.builder().authorityName(authority.getAuthorityName()).build())
                        .collect(Collectors.toSet()))
                .build();
    }

}
