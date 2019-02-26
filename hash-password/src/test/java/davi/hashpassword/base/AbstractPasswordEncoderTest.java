package davi.hashpassword.base;

import static davi.hashpassword.base.TestUtils.getPassword;
import static davi.hashpassword.base.TestUtils.getPassword2;
import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.Test;

import davi.hashpassword.PasswordEncoder;

public abstract class AbstractPasswordEncoderTest<T extends PasswordEncoder> {

	protected T alg;

	public AbstractPasswordEncoderTest() {
		super();
	}

	@Test
	public void checkCorrectPasswordTest() {
		String hashed = alg.encode(getPassword());
		assertTrue(alg.matches(getPassword(), new String(hashed)));
	}

	@Test
	public void checkWrongPasswordTest() {
		String hashed = alg.encode(getPassword());
		assertFalse(alg.matches(getPassword2(), new String(hashed)));
	}
	
	@Test
	public abstract void sameHashForEqualPasswordsTest();	
}