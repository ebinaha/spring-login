package com.example.jwt.common;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.catalina.authenticator.SpnegoAuthenticator.AcceptAction;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

import lombok.RequiredArgsConstructor;

@Component @RequiredArgsConstructor
public class JwtAuthenticationInterceptor implements HandlerInterceptor {

	private final JwtTokenProvider jwtTokenProvider;
	
	@Override
	public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler)
			throws Exception {
		// request Header로 => 토큰 가져오기
		String token = jwtTokenProvider.resolveToken(request);
		
		System.out.println("token :"+token);
		
		// return false : controller까지 못 감, 코드를 response에 심어서 return false 처리
		// 1) 토큰이 비어있는 경우 : 로그인시 토큰 생성 전이기 때문에 로그인 처리로 보냄 => controller => 무조건적으로 토큰(2개)을 발급해줄것
		if(token==null) return true;
		
		String[] tokens = token.split(",");
		
		// 2) access 토큰이 유효한 경우 : 정상 처리
		if(jwtTokenProvider.validateToken(tokens[0])) {
			System.out.println("2. accessToken 유효");
			// 토큰을 하나 가져왔는데 타당하면 (만료시간 체크) 유저정보 체크 : 토큰의 PK를 가져와서 DB랑 비교
			// 토큰이 유효하면 토큰으로부터 유저 정보를 받아옴
			Authentication authentication = jwtTokenProvider.getAuthentication(token);
			// Security Context에 Authentication 객체를 저장
			SecurityContextHolder.getContext().setAuthentication(authentication);
			return true;
		} else if(tokens.length == 1) { // 3-1) access 토큰만 가져왔는데 만료되었을 경우(토큰O, 타당X) : refresh 토큰 요청
			System.out.println("3. refreshToken 요청");
			response.setStatus(HttpServletResponse.SC_UNAUTHORIZED); // 에러코드 401
			// JSON 형태로 변환 : GSON 사용하기도 함
			// 100 : 토큰 만료, 리프레시 토큰 재요청 
			response.getWriter().write("{\"rescode\":\"100}");
			response.getWriter().flush();
		} else if (jwtTokenProvider.validateToken(tokens[1])) { // 3-2) access, refresh 토큰 유효 : 새로운 2개의 토큰 재발급
			System.out.println("4. refreshToken 유효");
			response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
			String userPk = jwtTokenProvider.getUserPk(tokens[1]);
//			String accssToken = jwtTokenProvider.createToken(userPk);
			String accssToken = jwtTokenProvider.createToken2(userPk); //테스트
			String refreshToken = jwtTokenProvider.refreshToken(userPk);
			// 101 : ?
			response.getWriter().write("{\"rescode\":101,\"accessToken\":\""+accssToken+"\",\"refreshToken\":\""+refreshToken+"\"}");
			response.getWriter().flush();
			
		} else { // 4) 두개의 토큰 모두 유효하지 않은 경우 : 재로그인 요청
			System.out.println("5. refreshToken 만료 => 재로그인 요청");
			response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
			// 102 : 둘 다 만료됨, 재로그인 요청
			response.getWriter().write("{\"rescode\":102}");
			response.getWriter().flush();
		}
		// 3~4 일 경우 false : response에서 응답을 내려줌
		return false;
	}
	
	

}
