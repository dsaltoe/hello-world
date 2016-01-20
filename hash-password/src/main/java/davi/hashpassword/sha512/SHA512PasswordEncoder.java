package davi.hashpassword.sha512;

import davi.hashpassword.PasswordEncoder;

public class SHA512PasswordEncoder implements PasswordEncoder {

	@Override
	public String encode(String password) {
		try {
			return SHA512.hashText(password);
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	@Override
	public boolean matches(String password, String hashed1) {
		String passwordHash;
		try {
			passwordHash = SHA512.hashText(password);
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
		return passwordHash.equals(hashed1);
	}

}
