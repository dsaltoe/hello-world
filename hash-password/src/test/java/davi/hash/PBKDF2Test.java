package davi.hash;

import static org.junit.Assert.*;

import org.junit.Before;
import org.junit.Test;
import org.mindrot.jbcrypt.BCrypt;

import davi.hashpassword.bcrypt.BCryptAlgorithm;
import davi.hashpassword.pbkdf2.PBKDF2Algorithm;

public class PBKDF2Test extends AbstractHashTest {

	@Before
	public void before() {
		alg = new PBKDF2Algorithm();
	}
	
}
