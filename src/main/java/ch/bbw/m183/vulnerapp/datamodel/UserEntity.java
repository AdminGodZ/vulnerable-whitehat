package ch.bbw.m183.vulnerapp.datamodel;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Getter;
import lombok.Setter;
import lombok.experimental.Accessors;

@Getter
@Setter
@Accessors(chain = true)
@Entity
@Table(name = "users")
public class UserEntity {

	@Id
	@NotBlank
	@Size(min = 3, max = 30)
	@Pattern(regexp = "^[A-Za-z0-9._-]+$")
	@Column(nullable = false, length = 30, updatable = false)
	String username;

	@NotBlank
	@Size(min = 2, max = 80)
	@Column(nullable = false, length = 80)
	String fullname;

	@NotBlank
	@Size(min = 8, max = 72)
	@Column(nullable = false, length = 100)
	String password;

	@NotBlank
	@Pattern(regexp = "^(USER|ADMIN)$")
	@Column(nullable = false)
	String role = UserRole.USER.name();
}
