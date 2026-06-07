package ch.bbw.m183.vulnerapp.service;

import java.io.IOException;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

@Component
@RequiredArgsConstructor
public class LoginRateLimitFilter extends OncePerRequestFilter {

	private final LoginAttemptService loginAttemptService;

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		if (isLoginRequest(request)) {
			var retryAfter = loginAttemptService.retryAfter(request.getParameter("username"), request.getRemoteAddr());
			if (!retryAfter.isZero()) {
				// Nach zu vielen Fehlversuchen wird hier blockiert, bevor Spring das Passwort prueft.
				response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
				response.setHeader("Retry-After", String.valueOf(retryAfter.toSeconds()));
				return;
			}
		}
		filterChain.doFilter(request, response);
	}

	private boolean isLoginRequest(HttpServletRequest request) {
		return HttpMethod.POST.matches(request.getMethod()) && "/login".equals(request.getServletPath());
	}
}
