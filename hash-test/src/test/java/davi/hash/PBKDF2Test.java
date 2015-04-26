package davi.hash;

import static org.junit.Assert.*;

import org.junit.Before;
import org.junit.Test;
import org.mindrot.jbcrypt.BCrypt;

public class PBKDF2Test extends AbstractHashTest {

	@Before
	public void before() {
		alg = new BCryptAlgorithm(12);
	}
	
}
