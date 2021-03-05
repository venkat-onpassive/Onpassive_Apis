package com.onpassive.omail.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.onpassive.omail.responsedto.LoginRequest;
import com.onpassive.omail.responsedto.ValidateTokenRequest;
import com.onpassive.omail.security.ApiResponse;
import com.onpassive.omail.security.JwtAuthenticationResponse;
import com.onpassive.omail.security.JwtTokenProvider;
import com.onpassive.omail.util.MessageConstants;

@RestController
@RequestMapping("/api/auth")
public class AuthController {
	
	private static final Logger logger = LoggerFactory.getLogger(AuthController.class);

	@Autowired
	AuthenticationManager authenticationManager;

	@Autowired
	JwtTokenProvider tokenProvider;

	@SuppressWarnings({ "unchecked", "rawtypes" })
	@PostMapping("/generatetoken")
	public ResponseEntity<?> authenticateUser(@RequestBody LoginRequest loginRequest) {
		if (loginRequest.getUsername().isEmpty() || loginRequest.getPassword().isEmpty()) {
			logger.info("Username or Password should not be empty");
			return new ResponseEntity(new ApiResponse(false, MessageConstants.USERNAME_OR_PASSWORD_INVALID),
					HttpStatus.BAD_REQUEST);
		}
		Authentication authentication = authenticationManager.authenticate(
				new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));
		String jwt = tokenProvider.generateToken(authentication);
		return ResponseEntity.ok(new JwtAuthenticationResponse(jwt));
	}

	@SuppressWarnings({ "unchecked", "rawtypes" })
	@PostMapping("/validatetoken")
	public ResponseEntity<?> getTokenByCredentials(@RequestBody ValidateTokenRequest validateToken) {
		String username = null;
		String jwt = validateToken.getToken();
		if (StringUtils.hasText(jwt) && tokenProvider.validateToken(jwt)) {
			username = tokenProvider.getUsernameFromJWT(jwt);
			logger.info("valid token");
			// If required we can have one more check here to load the user from LDAP server
			return ResponseEntity.ok(new ApiResponse(Boolean.TRUE, MessageConstants.VALID_TOKEN + username));
		} else {
			logger.info("invalid token");
			return new ResponseEntity(new ApiResponse(false, MessageConstants.INVALID_TOKEN), HttpStatus.BAD_REQUEST);
		}

	}
}