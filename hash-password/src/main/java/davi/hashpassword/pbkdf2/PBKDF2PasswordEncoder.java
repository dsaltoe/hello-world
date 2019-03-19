package davi.hashpassword.pbkdf2;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import davi.hashpassword.KeyStretchingPasswordManager;

public class PBKDF2PasswordEncoder implements KeyStretchingPasswordManager {


	public PBKDF2PasswordEncoder() {
		// TODO algorithm parameters
	}

	@Override
	public String genSalt() {
        return new String(PasswordHash.generateSalt());
	}

	@Override
	public String hash(String password, String salt) {
		try {
			return PasswordHash.createHash(password.toCharArray(), salt.getBytes());
		} catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
			throw new IllegalStateException(e);
		}
    }

	@Override
	public String hash(String password) {
		return hash(password, genSalt());
	}
	
	@Override
	public boolean matches(String password, String hashed) {
		try {
			return PasswordHash.validatePassword(password, hashed);
		} catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
			throw new IllegalStateException(e);
		}
    }

}
