package com.example.jwt.common;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

//@EnableWebSecurity
//public class SecurityConfig extends WebSecurityConfigurerAdapter {
//	
//	// security filterchain 으로 변경 : extend 안 받음
//	@Override
//	protected void configure(HttpSecurity http) throws Exception {
//		http.csrf().disable();
//		http.httpBasic().disable().authorizeHttpRequests().antMatchers("/login/**","/web-respirces/**", "/actuator/**").permitAll()	//전체 허용
//		.antMatchers("/admin/**").hasRole("ADMIN")
//		.antMatchers("/user/**").hasRole("USER")
//		.anyRequest().authenticated();	//나머지는 권한 체크
//		
//		http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
//	}
//}

@EnableWebSecurity
public class SecurityConfig {
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.cors().and().csrf().disable();
        http.httpBasic().disable().authorizeRequests()
                .antMatchers("/**/*").permitAll()
//                .antMatchers("/login**").permitAll()
//                .antMatchers("/admin/**").hasRole("ADMIN")
//                .antMatchers("/user/**").hasRole("USER")
                .anyRequest().authenticated();
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
        return http.build();
    }
}