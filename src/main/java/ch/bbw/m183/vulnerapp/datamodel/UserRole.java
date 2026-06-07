package ch.bbw.m183.vulnerapp.datamodel;

import java.util.Locale;

public enum UserRole {
	USER,
	ADMIN;

	public static String normalize(String role) {
		if (role == null || role.isBlank()) {
			return USER.name();
		}
		var normalizedRole = role.trim().toUpperCase(Locale.ROOT);
		if (normalizedRole.startsWith("ROLE_")) {
			normalizedRole = normalizedRole.substring("ROLE_".length());
		}
		for (var userRole : values()) {
			if (userRole.name().equals(normalizedRole)) {
				return normalizedRole;
			}
		}
		throw new IllegalArgumentException("Role must be USER or ADMIN");
	}
}
