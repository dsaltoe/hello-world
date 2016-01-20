package davi.hashpassword.pbkdf2;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import davi.hashpassword.KeyStretchingPasswordEncoder;

public class PBKDF2PasswordEncoder implements KeyStretchingPasswordEncoder {


	public PBKDF2PasswordEncoder() {
		// TODO algorithm parameters
	}

	@Override
	public String genSalt() {
        return String.valueOf(PasswordHash.generateSalt());
	}

	@Override
	public String encode(String password, String salt) {
		try {
			return PasswordHash.createHash(password.toCharArray(), salt.getBytes());
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException(e);
		} catch (InvalidKeySpecException e) {
			throw new IllegalStateException(e);
		}
	}

	@Override
	public String encode(String password) {
		return encode(password, genSalt());
	}
	
	@Override
	public boolean matches(String password, String hashed) {
		try {
			return PasswordHash.validatePassword(password, hashed);
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException(e);
		} catch (InvalidKeySpecException e) {
			throw new IllegalStateException(e);
		}
	}

}
