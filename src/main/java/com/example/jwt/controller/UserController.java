package com.example.jwt.controller;

import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.example.jwt.common.JwtTokenProvider;
import com.example.jwt.entity.User;
import com.example.jwt.service.CustomUserDetailsService;

import lombok.RequiredArgsConstructor;

@RestController 
@RequiredArgsConstructor
public class UserController {
	private final CustomUserDetailsService customUserDetailsService;
	private final JwtTokenProvider jwtTokenProvider;
	
	@PostMapping("/login")
	public ResponseEntity<Map<String, String>> login(@RequestParam("id") String id, @RequestParam("password") String password, HttpServletRequest request){
		Map<String, String> res = new HashMap<>();
		User user = (User)customUserDetailsService.loadUserByUsername(id);
		String accessToken = jwtTokenProvider.createToken(user.getUsername());
		String refreshToken = jwtTokenProvider.refreshToken(user.getUsername());
		// id만 넣어도 ok
		res.put("userid", user.getUsername());
		res.put("accessToken", accessToken);
		res.put("refreshToken", refreshToken);
		
		return new ResponseEntity<Map<String, String>>(res, HttpStatus.OK);
	}
	
	@GetMapping("/userInfo")
	public ResponseEntity<User> userInfo(@RequestParam("id") String id){
		User user = (User)customUserDetailsService.loadUserByUsername(id);
		return new ResponseEntity<User> (user, HttpStatus.OK); 
	}
	
}
