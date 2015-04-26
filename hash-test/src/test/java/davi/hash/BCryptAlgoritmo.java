package davi.hash;

import org.mindrot.jbcrypt.BCrypt;

public class BCryptAlgoritmo extends Algoritmo {

	private int log_rounds;

	public BCryptAlgoritmo(int log_rounds) {
		this.log_rounds = log_rounds;
	}

	@Override
	public String genSalt() {
		return BCrypt.gensalt(log_rounds);
	}

	@Override
	public String hash(String password, String salt) {
		return BCrypt.hashpw(new String(password), new String(salt));
	}

	@Override
	public boolean check(String password, String hashed) {
		return BCrypt.checkpw(new String(password), new String(hashed));
	}

}
