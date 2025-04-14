package com.springboot.oauth;

import com.springboot.member.entity.Member;
import com.springboot.member.repository.MemberRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import java.util.stream.Collectors;

@RequiredArgsConstructor
@Component
public class OAuthAuthenticationProvider implements AuthenticationProvider {

    private final MemberRepository memberRepository;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        // 인증정보에서 principal 가져오기 = email
        String email = (String) authentication.getPrincipal();

        // principal 에서 가져온 email 로 member 찾기
        Member member = memberRepository.findByEmail(email)
                // 없으면 없다고 이메일과 함께 알려줌
                .orElseThrow(() -> new UsernameNotFoundException("해당 이메일 없음: " + email));
        // accessToken 을 만들기 위한 설계도에 email 과 역할 부여
        return new OAuthAuthenticationToken(email,
                member.getRoles().stream()
                        .map(role -> new SimpleGrantedAuthority(role))
                        .collect(Collectors.toList())); // 권한 세팅 포함 가능
    }

    @Override
    // AuthenticationProvider 가 처리할 수 있는 Authentication 타입인지 확인하는 메서드
    // 얘가 true 가 나와야 provider 가 실행됨
    public boolean supports(Class<?> authentication) {
        // 파라미터로 받는 authentication 이 OAuthAuthenticationToken.class 이거나
        // 그 하위 클래스라면 true 반환
        return OAuthAuthenticationToken.class.isAssignableFrom(authentication);
    }
}