package com.example.jwt.common;


import java.util.Base64;
import java.util.Date;

import javax.annotation.PostConstruct;
import javax.servlet.http.HttpServletRequest;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.RequiredArgsConstructor;

@Component @RequiredArgsConstructor
public class JwtTokenProvider {
	// 임시 토큰 지정
	private String secretKey = "myprojectsecretkeyforjwttokenanythingwriteonmyproject";
	
	// ms단위의 시간 : long, 계산식의 하나 이상을 L으로 만들어주어야 함
	// 토큰 유효시간 : 1시간
	private long tokenValidTime = 60*60*1000L;
	
	private final UserDetailsService userDetailsService;
	
	// 생성된 후 주입될 때(다른 객체에 주입되기 전에) 호출
	// @RequiredArgsConstructor를 통해 생성자에 주입되거나 @Autowired로 주입
	@PostConstruct
	protected void init() {
		secretKey = Base64.getEncoder().encodeToString(secretKey.getBytes());
	}
	
	/**
	 * JWT 토큰 생성
	 * @param userPk
	 * @return
	 */
	// token은 문자열 형태
	public String createToken(String userPk) {
		// JWT Payload : 데이터타입 Claims, 저장되는 정보단위 => 보통 user를 식별하는 값을 넣음
		// .put() : 으로 값을 추가적으로 넣을 수 있음
		Claims claims = Jwts.claims().setSubject(userPk);
//		claims.put("", "");

		Date now = new Date();
		return Jwts.builder().setClaims(claims).setId(userPk)
				.setIssuedAt(now) //만들어진 시간
				.setExpiration(new Date(now.getTime()+tokenValidTime)) // 만료 시간
				.signWith(SignatureAlgorithm.HS256, secretKey) // 알고리즘 이용 => key로 서명
				.compact();
		
	}

	/**
	 * Refresh 토큰 생성
	 * @param userPk
	 * @return
	 */
	public String refreshToken(String userPk) {
		Claims claims = Jwts.claims().setSubject(userPk);

		Date now = new Date();
		return Jwts.builder().setClaims(claims).setId(userPk)
				.setIssuedAt(now) //만들어진 시간
				.setExpiration(new Date(now.getTime()+tokenValidTime*5)) // 만료 시간
				.signWith(SignatureAlgorithm.HS256, secretKey) // 알고리즘 이용 => key로 서명
				.compact();
	}
	
	
	// 토큰에서 회원정보 추출 : setClaims 넣었었음?
	public String getUserPk(String token) {
		// 토큰에서 넣었던 userPk를 가져오는 것
		return Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token).getBody().getSubject();
	}
	
	// JWT 토큰에서 인증 정보 조회 : 가져온 것 인증, 타당성 체크? 인증을 위해 제공되는 클래스
	public Authentication getAuthentication (String token) {
		// key를 가지고 DB repository data 읽어오는 것 : userDetailsService
		UserDetails userDetails = userDetailsService.loadUserByUsername(this.getUserPk(token));
		
		// 인증 정보
		return new UsernamePasswordAuthenticationToken(userDetails, "", userDetails.getAuthorities());
	}
	
	// Request의 Header에서 AccessToken 값 추출 : "Authorization : token"
	public String resolveToken(HttpServletRequest request) {
		return request.getHeader("Authorization");
	}
	
	// 유효성 체크 : 토큰의 유효성 + 만료시간 확인
	public boolean validateToken (String jwtToken) {
		try {		
			Jws<Claims> claims = Jwts.parser().setSigningKey(secretKey).parseClaimsJws(jwtToken);
			// 가져온 시간이 현재시간보다 before면 만료 = false이기 때문에 ! 붙여줌 
			return !claims.getBody().getExpiration().before(new Date());
		} catch (Exception e) {
			return false;
		}
	} 
	
	
	
	
	
	
}
