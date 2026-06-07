package ch.bbw.m183.vulnerapp;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Optional;
import java.util.UUID;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseCookie;
import org.springframework.test.web.reactive.server.EntityExchangeResult;
import org.springframework.test.web.reactive.server.ExchangeResult;
import org.springframework.test.web.reactive.server.WebTestClient;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
		properties = "app.security.remember-me-key=test-remember-me-key-6a0d3ff6f8294d69a88ce0a89fd1094b")
class SecurityAccessTests {

	private static final String USERNAME = "fuu";
	private static final String USER_PASSWORD = "bar12345";
	private static final String ADMIN_USERNAME = "admin";
	private static final String ADMIN_PASSWORD = "super5ecret";

	@LocalServerPort
	int port;

	private WebTestClient client;

	@BeforeEach
	void setUp() {
		client = WebTestClient.bindToServer()
				.baseUrl("http://localhost:" + port)
				.build();
	}

	@Test
	void publicPagesAndBlogReadAreAllowedForEveryone() {
		var user = login(USERNAME, USER_PASSWORD);
		var admin = login(ADMIN_USERNAME, ADMIN_PASSWORD);

		client.get().uri("/")
				.exchange()
				.expectStatus().isOk();
		authenticatedGet(user, "/")
				.expectStatus().isOk();
		authenticatedGetWithCsrf(admin, "/")
				.expectStatus().isOk();

		client.get().uri("/api/blog")
				.exchange()
				.expectStatus().isOk();
		client.get().uri("/api/user/csrf")
				.exchange()
				.expectStatus().isOk()
				.expectCookie().exists("XSRF-TOKEN");
		authenticatedGet(user, "/api/blog")
				.expectStatus().isOk();
		authenticatedGetWithCsrf(admin, "/api/blog")
				.expectStatus().isOk();
	}

	@Test
	void postBlogRequiresAuthenticationAndValidCsrfToken() {
		var user = login(USERNAME, USER_PASSWORD);
		var admin = login(ADMIN_USERNAME, ADMIN_PASSWORD);

		client.post().uri("/api/blog")
				.contentType(MediaType.APPLICATION_JSON)
				.bodyValue(blogJson("anonymous"))
				.exchange()
				.expectStatus().isForbidden();

		authenticatedPostWithoutCsrf(user, "/api/blog", blogJson("user-without-csrf"))
				.expectStatus().isForbidden();

		authenticatedPostWithCsrf(user, "/api/blog", blogJson("user-with-csrf"))
				.expectStatus().isOk();

		authenticatedPostWithCsrf(admin, "/api/blog", blogJson("admin-with-csrf"))
				.expectStatus().isOk();
	}

	@Test
	void whoamiRequiresAuthenticationButNoCsrfBecauseItIsAGetRequest() {
		var user = login(USERNAME, USER_PASSWORD);
		var admin = login(ADMIN_USERNAME, ADMIN_PASSWORD);

		client.get().uri("/api/user/whoami")
				.exchange()
				.expectStatus().isUnauthorized();

		authenticatedGet(user, "/api/user/whoami")
				.expectStatus().isOk()
				.expectBody()
				.jsonPath("$.username").isEqualTo(USERNAME);

		authenticatedGetWithCsrf(user, "/api/user/whoami")
				.expectStatus().isOk()
				.expectBody()
				.jsonPath("$.username").isEqualTo(USERNAME);

		authenticatedGetWithCsrf(admin, "/api/user/whoami")
				.expectStatus().isOk()
				.expectBody()
				.jsonPath("$.username").isEqualTo(ADMIN_USERNAME);
	}

	@Test
	void adminEndpointsRequireAdminRole() {
		var user = login(USERNAME, USER_PASSWORD);
		var admin = login(ADMIN_USERNAME, ADMIN_PASSWORD);

		client.get().uri("/api/admin123/users")
				.exchange()
				.expectStatus().isUnauthorized();

		authenticatedGet(user, "/api/admin123/users")
				.expectStatus().isForbidden();

		authenticatedGetWithCsrf(user, "/api/admin123/users")
				.expectStatus().isForbidden();

		authenticatedGetWithCsrf(admin, "/api/admin123/users")
				.expectStatus().isOk();
	}

	@Test
	void adminPostRequiresAdminRoleAndCsrfToken() {
		var user = login(USERNAME, USER_PASSWORD);
		var admin = login(ADMIN_USERNAME, ADMIN_PASSWORD);
		var newUsername = "test-" + UUID.randomUUID().toString().substring(0, 8);
		var newUserJson = """
				{"username":"%s","fullname":"Test User","password":"test12345","role":"USER"}
				""".formatted(newUsername);

		authenticatedPostWithoutCsrf(admin, "/api/admin123/users", newUserJson)
				.expectStatus().isForbidden();

		authenticatedPostWithCsrf(user, "/api/admin123/users", newUserJson)
				.expectStatus().isForbidden();

		authenticatedPostWithCsrf(admin, "/api/admin123/users", newUserJson)
				.expectStatus().isCreated()
				.expectBody()
				.jsonPath("$.username").isEqualTo(newUsername)
				.jsonPath("$.role").isEqualTo("USER");
	}

	@Test
	void actuatorHealthIsPublicButOtherActuatorEndpointsRequireAdmin() {
		var user = login(USERNAME, USER_PASSWORD);
		var admin = login(ADMIN_USERNAME, ADMIN_PASSWORD);

		client.get().uri("/actuator/health")
				.exchange()
				.expectStatus().isOk()
				.expectBody(String.class)
				.value(body -> assertThat(body).contains("UP").doesNotContain("components"));

		authenticatedGet(user, "/actuator/health")
				.expectStatus().isOk();

		authenticatedGetWithCsrf(admin, "/actuator/health")
				.expectStatus().isOk();

		client.get().uri("/actuator")
				.exchange()
				.expectStatus().isUnauthorized();

		authenticatedGet(user, "/actuator")
				.expectStatus().isForbidden();

		authenticatedGetWithCsrf(admin, "/actuator")
				.expectStatus().isOk();
	}

	@Test
	void rememberMeCookieAuthenticatesWithoutSessionCookie() {
		var user = login(USERNAME, USER_PASSWORD, true);
		assertThat(user.rememberMeCookie())
				.as("remember-me cookie")
				.isPresent();
		var rememberMeCookie = user.rememberMeCookie().orElseThrow();
		assertThat(rememberMeCookie.getValue())
				.isNotEqualTo(USER_PASSWORD)
				.doesNotContain(USER_PASSWORD);
		assertThat(rememberMeCookie.isHttpOnly()).isTrue();
		assertThat(rememberMeCookie.getPath()).isEqualTo("/");
		assertThat(rememberMeCookie.getMaxAge().getSeconds()).isGreaterThan(0);

		client.get().uri("/api/user/whoami")
				.cookie("VULNERAPP_REMEMBER_ME", rememberMeCookie.getValue())
				.exchange()
				.expectStatus().isOk()
				.expectBody()
				.jsonPath("$.username").isEqualTo(USERNAME);
	}

	@Test
	void failedLoginAttemptsAreTemporarilyBlocked() {
		var admin = login(ADMIN_USERNAME, ADMIN_PASSWORD);
		var username = "limit-" + UUID.randomUUID().toString().substring(0, 8);
		var password = "valid12345";
		var newUserJson = """
				{"username":"%s","fullname":"Limited User","password":"%s","role":"USER"}
				""".formatted(username, password);

		authenticatedPostWithCsrf(admin, "/api/admin123/users", newUserJson)
				.expectStatus().isCreated();

		for (var i = 0; i < 5; i++) {
			submitLogin(username, "wrong12345", false, HttpStatus.UNAUTHORIZED);
		}

		var blockedResult = submitLogin(username, password, false, HttpStatus.TOO_MANY_REQUESTS);
		assertThat(blockedResult.getResponseHeaders().getFirst("Retry-After")).isNotBlank();
		assertThat(Optional.ofNullable(blockedResult.getResponseBody()).orElse("")).isEmpty();
	}

	@Test
	void securityHeadersAreSent() {
		assertSecurityHeaders("/", HttpStatus.OK);
		assertSecurityHeaders("/script.js", HttpStatus.OK);
		assertSecurityHeaders("/style.css", HttpStatus.OK);
		assertSecurityHeaders("/api/blog", HttpStatus.OK);
		assertSecurityHeaders("/api/user/csrf", HttpStatus.OK);
		assertSecurityHeaders("/api/user/whoami", HttpStatus.UNAUTHORIZED);
	}

	@Test
	void errorResponsesDoNotExposeInternalDetails() {
		var admin = login(ADMIN_USERNAME, ADMIN_PASSWORD);
		var newUsername = "invalid-" + UUID.randomUUID().toString().substring(0, 8);
		var invalidUserJson = """
				{"username":"%s","fullname":"Invalid User","password":"short","role":"USER"}
				""".formatted(newUsername);

		var invalidUserResult = authenticatedPostWithCsrf(admin, "/api/admin123/users", invalidUserJson)
				.expectStatus().isBadRequest()
				.expectBody(String.class)
				.returnResult();
		var invalidUserBody = Optional.ofNullable(invalidUserResult.getResponseBody()).orElse("");
		assertThat(invalidUserBody)
				.contains("Invalid request")
				.doesNotContain("Password must")
				.doesNotContain("MethodArgumentNotValidException")
				.doesNotContain("stackTrace")
				.doesNotContain("trace");

		var failedLoginResult = submitLogin("missing-" + UUID.randomUUID().toString().substring(0, 8),
				"wrong12345", false, HttpStatus.UNAUTHORIZED);
		var failedLoginBody = Optional.ofNullable(failedLoginResult.getResponseBody()).orElse("");
		assertThat(failedLoginBody).isEmpty();
		assertThat(failedLoginBody)
				.doesNotContain("Bad credentials")
				.doesNotContain("Invalid username")
				.doesNotContain("UsernameNotFoundException");

		var wrongPasswordResult = submitLogin(USERNAME, "wrong12345", false, HttpStatus.UNAUTHORIZED);
		var wrongPasswordBody = Optional.ofNullable(wrongPasswordResult.getResponseBody()).orElse("");
		assertThat(wrongPasswordBody).isEmpty();
		assertThat(wrongPasswordBody)
				.doesNotContain("Bad credentials")
				.doesNotContain("Invalid username")
				.doesNotContain("UsernameNotFoundException");
	}

	private void assertSecurityHeaders(String path, HttpStatus expectedStatus) {
		var result = client.get().uri(path)
				.exchange()
				.expectStatus().isEqualTo(expectedStatus)
				.returnResult();
		var headers = result.getResponseHeaders();
		assertThat(headers.getFirst("Content-Security-Policy"))
				.contains("default-src 'self'")
				.contains("script-src 'self' https://cdn.jsdelivr.net")
				.contains("frame-ancestors 'none'");
		assertThat(headers.getFirst("X-Frame-Options")).isEqualTo("DENY");
		assertThat(headers.getFirst("X-Content-Type-Options")).isEqualTo("nosniff");
		assertThat(headers.getFirst("Referrer-Policy")).isEqualTo("same-origin");
		assertThat(headers.getFirst("Permissions-Policy"))
				.contains("camera=()")
				.contains("microphone=()")
				.contains("geolocation=()");
		assertThat(headers.getFirst("Strict-Transport-Security"))
				.contains("max-age=31536000")
				.contains("includeSubDomains");
	}

	private WebTestClient.ResponseSpec authenticatedGet(AuthSession session, String path) {
		return client.get().uri(path)
				.cookie("JSESSIONID", session.sessionId())
				.cookie("XSRF-TOKEN", session.csrfToken())
				.exchange();
	}

	private WebTestClient.ResponseSpec authenticatedGetWithCsrf(AuthSession session, String path) {
		return client.get().uri(path)
				.cookie("JSESSIONID", session.sessionId())
				.cookie("XSRF-TOKEN", session.csrfToken())
				.header("X-XSRF-TOKEN", session.csrfToken())
				.exchange();
	}

	private WebTestClient.ResponseSpec authenticatedPostWithoutCsrf(AuthSession session, String path, String json) {
		return client.post().uri(path)
				.cookie("JSESSIONID", session.sessionId())
				.cookie("XSRF-TOKEN", session.csrfToken())
				.contentType(MediaType.APPLICATION_JSON)
				.bodyValue(json)
				.exchange();
	}

	private WebTestClient.ResponseSpec authenticatedPostWithCsrf(AuthSession session, String path, String json) {
		return client.post().uri(path)
				.cookie("JSESSIONID", session.sessionId())
				.cookie("XSRF-TOKEN", session.csrfToken())
				.header("X-XSRF-TOKEN", session.csrfToken())
				.contentType(MediaType.APPLICATION_JSON)
				.bodyValue(json)
				.exchange();
	}

	private AuthSession login(String username, String password) {
		return login(username, password, false);
	}

	private AuthSession login(String username, String password, boolean rememberMe) {
		var loginResult = submitLogin(username, password, rememberMe, HttpStatus.OK);
		var sessionId = requiredCookie(loginResult, "JSESSIONID");
		var freshCsrf = fetchCsrfToken(Optional.of(sessionId));
		return new AuthSession(sessionId, freshCsrf, optionalCookie(loginResult, "VULNERAPP_REMEMBER_ME"));
	}

	private EntityExchangeResult<String> submitLogin(String username, String password, boolean rememberMe, HttpStatus expectedStatus) {
		var csrf = fetchCsrfToken(Optional.empty());
		var formData = "username=" + username + "&password=" + password;
		if (rememberMe) {
			formData += "&remember-me=on";
		}
		return client.post().uri("/login")
				.cookie("XSRF-TOKEN", csrf)
				.header("X-XSRF-TOKEN", csrf)
				.contentType(MediaType.APPLICATION_FORM_URLENCODED)
				.bodyValue(formData)
				.exchange()
				.expectStatus().isEqualTo(expectedStatus)
				.expectBody(String.class)
				.returnResult();
	}

	private String fetchCsrfToken(Optional<String> sessionId) {
		var request = client.get().uri("/api/user/csrf");
		sessionId.ifPresent(value -> request.cookie("JSESSIONID", value));
		var result = request.exchange()
				.expectStatus().isOk()
				.returnResult();
		return requiredCookie(result, "XSRF-TOKEN");
	}

	private String requiredCookie(ExchangeResult result, String name) {
		var cookie = result.getResponseCookies().getFirst(name);
		assertThat(cookie)
				.as("response cookie %s", name)
				.isNotNull();
		return cookie.getValue();
	}

	private Optional<ResponseCookie> optionalCookie(ExchangeResult result, String name) {
		return Optional.ofNullable(result.getResponseCookies().getFirst(name))
				.map(cookie -> cookie);
	}

	private String blogJson(String suffix) {
		return """
				{"title":"Security test %s","body":"This body is valid and harmless."}
				""".formatted(suffix);
	}

	private record AuthSession(String sessionId, String csrfToken, Optional<ResponseCookie> rememberMeCookie) {
	}
}
