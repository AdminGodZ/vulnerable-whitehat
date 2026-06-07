package ch.bbw.m183.vulnerapp.service;

import java.util.stream.Stream;

import ch.bbw.m183.vulnerapp.datamodel.UserEntity;
import ch.bbw.m183.vulnerapp.datamodel.UserRole;
import ch.bbw.m183.vulnerapp.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.context.event.EventListener;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

@Service
@Transactional
@RequiredArgsConstructor
public class AdminService {

	private final UserRepository userRepository;
	private final PasswordEncoder passwordEncoder;

	@PreAuthorize("hasRole('ADMIN')")
	public UserEntity createUser(UserEntity newUser) {
		validatePassword(newUser.getPassword());
		newUser.setPassword(passwordEncoder.encode(newUser.getPassword()));
		newUser.setRole(normalizeRole(newUser.getRole()));
		return userRepository.save(newUser);
	}

	@PreAuthorize("hasRole('ADMIN')")
	public Page<UserEntity> getUsers(Pageable pageable) {
		return userRepository.findAll(pageable);
	}

	@PreAuthorize("hasRole('ADMIN')")
	public void deleteUser(String username) {
		userRepository.deleteById(username);
	}

	@EventListener(ContextRefreshedEvent.class)
	public void loadTestUsers() {
		Stream.of(new UserEntity().setUsername("admin").setFullname("Super Admin").setPassword("super5ecret").setRole("ADMIN"),
						new UserEntity().setUsername("fuu").setFullname("Johanna Doe").setPassword("bar12345").setRole("USER"))
				.forEach(this::createUser);
	}

	private void validatePassword(String password) {
		// Simpler Passwort-Check: mindestens 8 Zeichen, mindestens ein Buchstabe und eine Zahl.
		// Danach wird immer gehasht; vorbereitete Werte wie "{noop}passwort" werden nicht akzeptiert.
		if (password == null || password.length() < 8) {
			throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Password must contain at least 8 characters");
		}
		var containsLetter = password.chars().anyMatch(Character::isLetter);
		var containsDigit = password.chars().anyMatch(Character::isDigit);
		if (!containsLetter || !containsDigit) {
			throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Password must contain letters and numbers");
		}
		if (password.startsWith("{")) {
			throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Password must be plain text and will be hashed by the server");
		}
	}

	private String normalizeRole(String role) {
		try {
			return UserRole.normalize(role);
		}
		catch (IllegalArgumentException ex) {
			throw new ResponseStatusException(HttpStatus.BAD_REQUEST, ex.getMessage(), ex);
		}
	}
}
