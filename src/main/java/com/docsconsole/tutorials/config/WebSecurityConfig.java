package com.docsconsole.tutorials.config;

import com.docsconsole.tutorials.service.UserDetailsServiceImpl;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig {

	@Bean
	public UserDetailsServiceImpl userDetailsService() {
		return  new UserDetailsServiceImpl();
	}
	@Bean
	public AuthenticationManager authenticationManager(HttpSecurity httpSecurity, UserDetailsService userDetailsService, BCryptPasswordEncoder bCryptPasswordEncoder) throws Exception {
		AuthenticationManagerBuilder authenticationManagerBuilder = httpSecurity.getSharedObject(AuthenticationManagerBuilder.class);
		authenticationManagerBuilder.userDetailsService(userDetailsService())
				.passwordEncoder(bCryptPasswordEncoder());
		return authenticationManagerBuilder.build();
	}

	@Bean
	public BCryptPasswordEncoder bCryptPasswordEncoder() {
		return new BCryptPasswordEncoder();
	}
	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		http
			.authorizeHttpRequests((requests) -> requests
				.antMatchers("/", "/home").hasAnyAuthority("APP_USER", "APP_ADMIN")
				.antMatchers("/admin").hasAnyAuthority( "APP_ADMIN")
				.antMatchers("/user").hasAnyAuthority( "APP_USER")
				.anyRequest().authenticated()
			)
			.formLogin((form) -> form.loginPage("/login").permitAll())
			.logout((logout) -> logout.permitAll());

			http.exceptionHandling().accessDeniedPage("/accessDenied");

		return http.build();
	}
}
