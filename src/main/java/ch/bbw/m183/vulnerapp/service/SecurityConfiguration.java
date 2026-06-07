package ch.bbw.m183.vulnerapp.service;

import jakarta.servlet.http.HttpServletResponse;

import ch.bbw.m183.vulnerapp.datamodel.UserSessionDto;
import ch.bbw.m183.vulnerapp.datamodel.UserRole;
import ch.bbw.m183.vulnerapp.repository.UserRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.SecurityFilterChain;
import tools.jackson.databind.ObjectMapper;

@Configuration
@EnableMethodSecurity
public class SecurityConfiguration {

	@Bean
	public UserDetailsService userDetailsService(UserRepository userRepository) {
		return username -> userRepository.findById(username)
				.map(dbUser -> {
					var role = UserRole.normalize(dbUser.getRole());
					return User.withUsername(dbUser.getUsername())
							.password(dbUser.getPassword())
							.roles(role)
							.build();
				})
				.orElseThrow(() -> new UsernameNotFoundException("User not found: " + username));
	}

	@Bean
	public PasswordEncoder passwordEncoder() {
		// BCrypt ist ein langsamer, gesalteter Passworthash und speichert nie das Klartext-Passwort.
		return new BCryptPasswordEncoder();
	}

	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http, ObjectMapper objectMapper,
			UserRepository userRepository, UserDetailsService userDetailsService,
			LoginAttemptService loginAttemptService, LoginRateLimitFilter loginRateLimitFilter,
			@Value("${app.security.remember-me-key}") String rememberMeKey) throws Exception {
		return http
				// CSRF ist bewusst aktiv: Spring erzeugt einen XSRF-TOKEN Cookie fuer das Vanilla-JS-Frontend.
				// Bei unsicheren Requests wie POST/DELETE muss derselbe Wert im X-XSRF-TOKEN Header stehen.
				// Fremde Seiten senden zwar Session-Cookies automatisch mit, koennen diesen Token aber nicht
				// aus unserer Origin lesen und daher keinen gueltigen Header mitschicken. Ohne passenden Header
				// blockt Spring Security den Request vor dem Controller.
				.csrf(csrf -> csrf.spa())
				.authorizeHttpRequests(auth -> auth
							.requestMatchers("/", "/index.html", "/script.js", "/robots.txt", "/favicon.ico", "/error")
							.permitAll()
							.requestMatchers(HttpMethod.GET, "/api/blog")
							.permitAll()
							.requestMatchers(HttpMethod.GET, "/api/user/csrf")
							.permitAll()
							.requestMatchers(HttpMethod.GET, "/actuator/health")
							.permitAll()
							.requestMatchers("/api/admin123/**", "/api/blog/health", "/actuator/**")
							.hasRole("ADMIN")
							.requestMatchers(HttpMethod.POST, "/api/blog")
							.hasAnyRole("USER", "ADMIN")
							.requestMatchers("/api/user/**")
							.hasAnyRole("USER", "ADMIN")
							.requestMatchers("/api/**")
							.authenticated()
							.anyRequest()
							.permitAll())
				.formLogin(form -> form
						.loginProcessingUrl("/login")
						.successHandler((request, response, authentication) -> {
							loginAttemptService.recordSuccess(authentication.getName(), request.getRemoteAddr());
							var user = userRepository.findById(authentication.getName()).orElseThrow();
							response.setStatus(HttpServletResponse.SC_OK);
							response.setContentType(MediaType.APPLICATION_JSON_VALUE);
							objectMapper.writeValue(response.getWriter(), UserSessionDto.from(user));
						})
						.failureHandler((request, response, exception) -> {
							loginAttemptService.recordFailure(request.getParameter("username"), request.getRemoteAddr());
							response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
						})
						.permitAll())
				.rememberMe(rememberMe -> rememberMe
						// Keep-Me-Logged-In speichert kein Passwort im Cookie.
						// Der geheime Key kommt aus der Konfiguration/Umgebung, damit er nicht im Code steht.
						// Spring signiert den Token damit und prueft ihn gegen UserDetails und Passwort-Hash.
						.key(rememberMeKey)
						.rememberMeParameter("remember-me")
						.rememberMeCookieName("VULNERAPP_REMEMBER_ME")
						.tokenValiditySeconds(14 * 24 * 60 * 60)
						.userDetailsService(userDetailsService))
				.logout(logout -> logout
						.logoutUrl("/logout")
						.logoutSuccessHandler((request, response, authentication) ->
								response.setStatus(HttpServletResponse.SC_NO_CONTENT))
						.permitAll())
				.exceptionHandling(exceptions -> exceptions
						.authenticationEntryPoint((request, response, authException) ->
								response.setStatus(HttpServletResponse.SC_UNAUTHORIZED)))
				.addFilterBefore(loginRateLimitFilter, UsernamePasswordAuthenticationFilter.class)
				.build();
	}
}
