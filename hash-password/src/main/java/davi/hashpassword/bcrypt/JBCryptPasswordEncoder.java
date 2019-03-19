package davi.hashpassword.bcrypt;

import org.mindrot.jbcrypt.BCrypt;

import davi.hashpassword.KeyStretchingPasswordManager;

public class JBCryptPasswordEncoder implements KeyStretchingPasswordManager {

	private final int logRounds;

	public JBCryptPasswordEncoder(int logRounds) {
		this.logRounds = logRounds;
	}

	@Override
	public String genSalt() {
		return BCrypt.gensalt(logRounds);
	}

	@Override
	public String hash(String password, String salt) {
		return BCrypt.hashpw(password, salt);
	}

	@Override
	public String hash(String password) {
		return hash(password, genSalt());
	}
	
	@Override
	public boolean matches(String password, String hashed) {
		return BCrypt.checkpw(password, hashed);
	}

}
