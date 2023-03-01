package com.example.jwtpractice.repository;

import com.example.jwtpractice.entity.Member;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface MemberRepository extends JpaRepository<Member, Long> {

    @EntityGraph(attributePaths = "authorities") // fetch 조인하여 authorities 정보까지 같이 조회. Lazy 조회가 아니라 Eager 조회.
    Optional<Member> findOneWithAuthoritiesByMemberName(String memberName); //유저정보 가져올 때 권한 정보도 같이 가져오는 메소드
}
