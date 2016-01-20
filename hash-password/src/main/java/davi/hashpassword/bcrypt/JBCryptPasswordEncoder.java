package davi.hashpassword.bcrypt;

import org.mindrot.jbcrypt.BCrypt;

import davi.hashpassword.KeyStretchingPasswordEncoder;

public class JBCryptPasswordEncoder implements KeyStretchingPasswordEncoder {

	private int log_rounds;

	public JBCryptPasswordEncoder(int log_rounds) {
		this.log_rounds = log_rounds;
	}

	@Override
	public String genSalt() {
		return BCrypt.gensalt(log_rounds);
	}

	@Override
	public String encode(String password, String salt) {
		return BCrypt.hashpw(new String(password), new String(salt));
	}

	@Override
	public String encode(String password) {
		return encode(password, genSalt());
	}
	
	@Override
	public boolean matches(String password, String hashed) {
		return BCrypt.checkpw(new String(password), new String(hashed));
	}

}
