package ch.bbw.m183.vulnerapp.controller;

import ch.bbw.m183.vulnerapp.datamodel.UserEntity;
import ch.bbw.m183.vulnerapp.datamodel.UserSessionDto;
import ch.bbw.m183.vulnerapp.service.AdminService;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpStatus;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/admin123") // noone will ever guess!
@Validated
@RequiredArgsConstructor
public class AdminController {

	private final AdminService adminService;

	@PostMapping("/users")
	@ResponseStatus(HttpStatus.CREATED)
	public UserSessionDto createUser(@Valid @RequestBody UserEntity newUser) {
		return UserSessionDto.from(adminService.createUser(newUser));
	}

	@GetMapping("/users")
	public Page<UserSessionDto> getUsers(Pageable pageable) {
		return adminService.getUsers(pageable).map(UserSessionDto::from);
	}

	@DeleteMapping("/users/{username}")
	@ResponseStatus(HttpStatus.NO_CONTENT)
	public void deleteUser(@PathVariable @NotBlank @Size(min = 3, max = 30) @Pattern(regexp = "^[A-Za-z0-9._-]+$") String username) {
		adminService.deleteUser(username);
	}
}
