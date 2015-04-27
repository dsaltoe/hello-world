package davi.hashpassword.pbkdf2;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;

import davi.hashpassword.HashAlgorithm;

public class PBKDF2Algorithm extends HashAlgorithm {


	public PBKDF2Algorithm() {
		// TODO algorithm parameters
	}

	@Override
	public String genSalt() {
        return String.valueOf(PasswordHash.generateSalt());
	}

	@Override
	public String hash(String password, String salt) {
		try {
			return PasswordHash.createHash(password.toCharArray(), salt.getBytes());
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException(e);
		} catch (InvalidKeySpecException e) {
			throw new IllegalStateException(e);
		}
	}

	@Override
	public boolean check(String password, String hashed) {
		try {
			return PasswordHash.validatePassword(password, hashed);
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException(e);
		} catch (InvalidKeySpecException e) {
			throw new IllegalStateException(e);
		}
	}

}
