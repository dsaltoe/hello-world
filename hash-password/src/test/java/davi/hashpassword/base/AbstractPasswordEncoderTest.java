package davi.hashpassword.base;

import static davi.hashpassword.base.TestUtils.getPassword;
import static davi.hashpassword.base.TestUtils.getPassword2;
import static org.junit.jupiter.api.Assertions.*;

import davi.hashpassword.KeyStretchingPasswordManager;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.regex.Pattern;

public abstract class AbstractPasswordEncoderTest<T extends KeyStretchingPasswordManager> {

	protected T alg;

	@BeforeEach
	public void before() {
		alg = createAlg(getDefaultRounds());
	}

	protected abstract T createAlg(Integer rounds);

	protected abstract Integer getDefaultRounds();

	protected abstract Pattern getHashRegex();

	public AbstractPasswordEncoderTest() {
		super();
	}

	@Test
	public void checkCorrectPasswordTest() {
		String hashed = alg.hash(getPassword());
		assertTrue(alg.matches(getPassword(), hashed));
	}

	@Test
	public void checkWrongPasswordTest() {
		String hashed = alg.hash(getPassword());
		assertFalse(alg.matches(getPassword2(), hashed));
	}
	
	@Test
	public abstract void equalPasswordsAndSaltsGenerateSameHashes();
}