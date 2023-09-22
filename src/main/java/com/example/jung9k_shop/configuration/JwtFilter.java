package com.example.jung9k_shop.configuration;

import java.io.IOException;
import java.util.List;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import com.example.jung9k_shop.service.UserService;
import com.example.jung9k_shop.utils.JwtTokenUtil;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@RequiredArgsConstructor
@Slf4j
public class JwtFilter extends OncePerRequestFilter {

	private final UserService userService;
	private final String key;

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
		FilterChain filterChain) throws ServletException, IOException {

		final String authorization = request.getHeader(HttpHeaders.AUTHORIZATION);
		log.info("authorization : {}", authorization);

		// token 안보내면 Block
		if (authorization == null || !authorization.startsWith("Bearer ")) {
			log.error("authorization을 잘못 보냈습니다.");
			filterChain.doFilter(request, response);
			return;
		}

		// Token 꺼내기
		String token = authorization.split(" ")[1];

		// Token Expired 되었는지 여부
		if (JwtTokenUtil.isExpired(token, key)) {
			log.error("Token이 만료되었습니다.");
			filterChain.doFilter(request, response);
			return;
		}

		// UserName Token에서 꺼내기
		String userName = JwtTokenUtil.getUserName(token, key);
		log.info("userName:{}", userName);

		// 권한 부여
		UsernamePasswordAuthenticationToken authenticationToken =
			new UsernamePasswordAuthenticationToken(userName, null, List.of(new SimpleGrantedAuthority("USER")));
		// Detail을 넣어줍니다.
		authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
		SecurityContextHolder.getContext().setAuthentication(authenticationToken);
		filterChain.doFilter(request, response);

	}
}
