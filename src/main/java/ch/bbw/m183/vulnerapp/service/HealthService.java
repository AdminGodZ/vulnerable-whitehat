package ch.bbw.m183.vulnerapp.service;

import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional
@RequiredArgsConstructor
public class HealthService {

	@PreAuthorize("hasRole('ADMIN')")
	public String health(String host) {
		// Gespeicherte Passwoerter sind BCrypt-Hashes und duerfen nie als Klartext-Secret weiterverwendet werden.
		return "UP";
	}
}
