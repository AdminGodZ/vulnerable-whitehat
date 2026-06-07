package ch.bbw.m183.vulnerapp.datamodel;

public record UserSessionDto(String username, String fullname, String role) {

	public static UserSessionDto from(UserEntity user) {
		return new UserSessionDto(user.getUsername(), user.getFullname(), user.getRole());
	}
}
