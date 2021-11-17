package com.devsuperior.bds04.config;

import java.util.Arrays;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;

@Configuration
@EnableResourceServer
public class ResourceServerConfig extends ResourceServerConfigurerAdapter {

	@Autowired
	private Environment env;
	
	@Autowired
	private JwtTokenStore tokenStore;
	
	private static final String[] PUBLIC = { "/oauth/token", "/h2-console/**" };	
	private static final String[] CLIENT_OR_ADMIN = { "/events/**", "/cities/**" };	
	private static final String[] CLIENT_OR_ADMIN_POST = { "/events/**" };	
	private static final String[] ADMIN_POST = { "/cities/**" };

	
	@Override
	public void configure(ResourceServerSecurityConfigurer resources) throws Exception {
		resources.tokenStore(tokenStore);
	}

	@Override
	public void configure(HttpSecurity http) throws Exception {

		/*
	 
	1) Os endpoints de login e do H2 devem ser públicos
	2) Os endpoints GET para /cities e /events devem ser públicos
	3) O endpoint POST de /events devem requerer login de ADMIN ou CLIENT
	4) Todos demais endpoints devem requerer login de ADMIN
	
		 */

		
		// H2
		if (Arrays.asList(env.getActiveProfiles()).contains("test")) {
			http.headers().frameOptions().disable();
		}
		
		http.authorizeRequests()
		.antMatchers(PUBLIC).permitAll()		
		.antMatchers(HttpMethod.GET, CLIENT_OR_ADMIN).permitAll()		
		.antMatchers(HttpMethod.POST, CLIENT_OR_ADMIN_POST).hasAnyRole("CLIENT", "ADMIN")		
		.antMatchers(HttpMethod.POST, ADMIN_POST).hasAnyRole("ADMIN")		
		.antMatchers(CLIENT_OR_ADMIN).hasAnyRole("CLIENT", "ADMIN")
		.anyRequest().hasAnyRole("ADMIN");
	}	
	
	
}