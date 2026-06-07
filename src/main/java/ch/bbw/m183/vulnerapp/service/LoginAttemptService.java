package ch.bbw.m183.vulnerapp.service;

import java.time.Duration;
import java.time.Instant;
import java.util.Locale;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.stereotype.Service;

@Service
public class LoginAttemptService {

	private static final int MAX_FAILED_ATTEMPTS = 5;
	private static final Duration FAILURE_WINDOW = Duration.ofMinutes(10);
	private static final Duration BLOCK_DURATION = Duration.ofMinutes(10);

	private final ConcurrentHashMap<String, LoginAttempt> attempts = new ConcurrentHashMap<>();

	public Duration retryAfter(String username, String remoteAddress) {
		var key = key(username, remoteAddress);
		var attempt = attempts.get(key);
		if (attempt == null || attempt.blockedUntil() == null) {
			return Duration.ZERO;
		}
		var now = Instant.now();
		if (attempt.blockedUntil().isAfter(now)) {
			return Duration.between(now, attempt.blockedUntil());
		}
		attempts.remove(key, attempt);
		return Duration.ZERO;
	}

	public void recordFailure(String username, String remoteAddress) {
		var now = Instant.now();
		cleanupExpired(now);
		var key = key(username, remoteAddress);
		attempts.compute(key, (ignored, current) -> {
			if (current != null && current.isBlocked(now)) {
				return current;
			}
			var failures = current == null || current.isExpired(now) ? 1 : current.failures() + 1;
			var blockedUntil = failures >= MAX_FAILED_ATTEMPTS ? now.plus(BLOCK_DURATION) : null;
			return new LoginAttempt(failures, blockedUntil, now);
		});
	}

	public void recordSuccess(String username, String remoteAddress) {
		attempts.remove(key(username, remoteAddress));
	}

	private String key(String username, String remoteAddress) {
		var normalizedUsername = Optional.ofNullable(username)
				.map(String::trim)
				.filter(value -> !value.isBlank())
				.map(value -> value.toLowerCase(Locale.ROOT))
				.orElse("<empty>");
		var normalizedAddress = Optional.ofNullable(remoteAddress).orElse("unknown");
		return normalizedUsername + "|" + normalizedAddress;
	}

	private void cleanupExpired(Instant now) {
		attempts.entrySet().removeIf(entry -> entry.getValue().isExpired(now));
	}

	private record LoginAttempt(int failures, Instant blockedUntil, Instant lastFailureAt) {

		private boolean isBlocked(Instant now) {
			return blockedUntil != null && blockedUntil.isAfter(now);
		}

		private boolean isExpired(Instant now) {
			if (isBlocked(now)) {
				return false;
			}
			return blockedUntil != null || lastFailureAt.plus(FAILURE_WINDOW).isBefore(now);
		}
	}
}
