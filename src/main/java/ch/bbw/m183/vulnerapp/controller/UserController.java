package ch.bbw.m183.vulnerapp.controller;

import java.util.Map;

import ch.bbw.m183.vulnerapp.datamodel.UserSessionDto;
import ch.bbw.m183.vulnerapp.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/user")
@RequiredArgsConstructor
public class UserController {

	private final UserService userService;

	@GetMapping("/whoami")
	public UserSessionDto whoami(Authentication authentication) {
		return userService.currentUser(authentication.getName());
	}

	@GetMapping("/csrf")
	public Map<String, String> csrf(CsrfToken csrfToken) {
		// Der Zugriff auf CsrfToken zwingt Spring, einen aktuellen XSRF-TOKEN Cookie zu erzeugen.
		// Das Frontend nutzt den Cookie-Wert danach fuer den X-XSRF-TOKEN Header.
		return Map.of("token", csrfToken.getToken());
	}
}
