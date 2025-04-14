package com.springboot.oauth;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class OAuthAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

    private final ObjectMapper objectMapper = new ObjectMapper();

    public OAuthAuthenticationFilter(String defaultFilterProcessesUrl, AuthenticationManager authManager) {
        super(defaultFilterProcessesUrl);
        setAuthenticationManager(authManager);
    }

    @Override
    // Authentication 객체를 만드는 메서드
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException, IOException {
        // 로그인 request 만듬 -> 요청에 담겨온 입력값 받아옴, OAuthLoginRequest class 로 받겠다는 의미
        OAuthLoginRequest loginRequest = objectMapper.readValue(request.getInputStream(), OAuthLoginRequest.class);
        // loginRequest 에서 email 을 뽑아서 인증 토큰 생성
        OAuthAuthenticationToken authRequest = new OAuthAuthenticationToken(loginRequest.getEmail());
        // 현재 AuthenticationManager 에서 authRequest 을 검증하고 검증 결과 반환
        return this.getAuthenticationManager().authenticate(authRequest);
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response,
                                            FilterChain chain, Authentication authResult) {
        // 토큰 생성 등 후처리 가능
    }
}
