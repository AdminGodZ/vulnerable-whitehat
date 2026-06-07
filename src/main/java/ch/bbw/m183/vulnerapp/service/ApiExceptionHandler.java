package ch.bbw.m183.vulnerapp.service;

import jakarta.validation.ConstraintViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.server.ResponseStatusException;

@RestControllerAdvice
public class ApiExceptionHandler {

	@ExceptionHandler({
			MethodArgumentNotValidException.class,
			ConstraintViolationException.class,
			HttpMessageNotReadableException.class
	})
	public ResponseEntity<ErrorMessage> handleBadRequest(Exception exception) {
		return error(HttpStatus.BAD_REQUEST);
	}

	@ExceptionHandler(ResponseStatusException.class)
	public ResponseEntity<ErrorMessage> handleResponseStatus(ResponseStatusException exception) {
		return error(exception.getStatusCode());
	}

	@ExceptionHandler(AccessDeniedException.class)
	public ResponseEntity<ErrorMessage> handleAccessDenied(AccessDeniedException exception) {
		return error(HttpStatus.FORBIDDEN);
	}

	@ExceptionHandler(Exception.class)
	public ResponseEntity<ErrorMessage> handleUnexpected(Exception exception) {
		return error(HttpStatus.INTERNAL_SERVER_ERROR);
	}

	private ResponseEntity<ErrorMessage> error(HttpStatusCode status) {
		// Details wie Exception-Klasse, Stacktrace oder konkrete Validierungsregel bleiben serverseitig.
		return ResponseEntity.status(status).body(new ErrorMessage(messageFor(status)));
	}

	private String messageFor(HttpStatusCode status) {
		if (status.isSameCodeAs(HttpStatus.BAD_REQUEST)) {
			return "Invalid request";
		}
		if (status.isSameCodeAs(HttpStatus.UNAUTHORIZED)) {
			return "Authentication required";
		}
		if (status.isSameCodeAs(HttpStatus.FORBIDDEN)) {
			return "Access denied";
		}
		if (status.isSameCodeAs(HttpStatus.NOT_FOUND)) {
			return "Not found";
		}
		return "Request failed";
	}

	private record ErrorMessage(String error) {
	}
}
