package jwt.config;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import io.jsonwebtoken.ExpiredJwtException;
import jwt.service.JwtUserDetailsService;

@Component
public class JwtRequestFilter extends OncePerRequestFilter{
	@Autowired
	private JwtUserDetailsService jwtUserDetailService;
	@Autowired
	private JwtTokenUtil jwtTokenUtil;
	
	//Every request must through here: 
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		final String requestTokenHeader = request.getHeader("Authorization");
		String username = null;
		String jwtToken = null;
		//jwt token is in the form "Bearer token". Remove Bearer word and get only token
		if(requestTokenHeader !=null && requestTokenHeader.startsWith("Bearer ")) {
			jwtToken = requestTokenHeader.substring(7);
			try {
				username = jwtTokenUtil.getUsernameFromToken(jwtToken);
			}catch(IllegalArgumentException e) {
				System.out.println("Unable to get JWT token");
			}catch(ExpiredJwtException e) {
				System.out.println("JWT token has expired");
			}
		}else {
			System.out.println("Jwt token does not begin with Bearere string");
		}
		//Once we get the token validate it:
		if(username!=null && SecurityContextHolder.getContext().getAuthentication()==null) {
			UserDetails userDetail = this.jwtUserDetailService.loadUserByUsername(username);
			//if token is valid configure Spring Security to manually set authentication
			if(jwtTokenUtil.validateToken(jwtToken, userDetail)) {
				UsernamePasswordAuthenticationToken userNameAuthen = 
						new UsernamePasswordAuthenticationToken(userDetail,null,userDetail.getAuthorities());
				userNameAuthen.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
				//After setting the authentication in the context, we specify
				// that the current user is authenticated. So it passes the Spring Security Configurations successfully
				SecurityContextHolder.getContext().setAuthentication(userNameAuthen);
			}
		}
		filterChain.doFilter(request, response);
		
	}
	
}
