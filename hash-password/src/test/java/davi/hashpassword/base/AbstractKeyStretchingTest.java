package davi.hashpassword.base;

import static davi.hashpassword.base.TestUtils.getPassword;
import static davi.hashpassword.base.TestUtils.getPassword2;
import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

import davi.hashpassword.KeyStretchingPasswordManager;

import java.util.regex.Matcher;

public abstract class AbstractKeyStretchingTest extends AbstractPasswordEncoderTest<KeyStretchingPasswordManager> {

	@Test
	public void equalPasswordsWithDifferentSaltsGenerateDifferentHashes() {
		String hashed1 = alg.hash(getPassword());
		String hashed2 = alg.hash(getPassword());

		assertNotEquals(hashed1, hashed2);
		
		assertTrue(alg.matches(getPassword(), hashed1));
		assertTrue(alg.matches(getPassword(), hashed2));
	}

	@Override
	@Test
	public void equalPasswordsAndSaltsGenerateSameHashes() {
		String salt = alg.genSalt();
		String hashed1 = alg.hash(getPassword(), salt);
		String hashed2 = alg.hash(getPassword(), salt);
		
		assertEquals(hashed1, hashed2);
	
		assertTrue(alg.matches(getPassword(), hashed1));
		assertTrue(alg.matches(getPassword(), hashed2));
	}

	@Test
	public void equalPasswordsWithDifferentRoundsTest() {
		KeyStretchingPasswordManager alg1 = createAlg(getDefaultRounds() + 1);
		KeyStretchingPasswordManager alg2 = createAlg(getDefaultRounds() + 2);
		KeyStretchingPasswordManager alg3 = createAlg(getDefaultRounds() + 3);

		String hashed1 = alg1.hash(getPassword(), alg.genSalt());
		String hashed2 = alg2.hash(getPassword(), alg.genSalt());

		assertNotEquals(hashed1, hashed2);

		assertTrue(alg1.matches(getPassword(), hashed1));
		assertTrue(alg1.matches(getPassword(), hashed2));
		assertTrue(alg2.matches(getPassword(), hashed1));
		assertTrue(alg2.matches(getPassword(), hashed2));
		assertTrue(alg3.matches(getPassword(), hashed1));
		assertTrue(alg3.matches(getPassword(), hashed2));

		assertFalse(alg1.matches(getPassword2(), hashed1));
		assertFalse(alg1.matches(getPassword2(), hashed2));
		assertFalse(alg2.matches(getPassword2(), hashed1));
		assertFalse(alg2.matches(getPassword2(), hashed2));
		assertFalse(alg3.matches(getPassword2(), hashed1));
		assertFalse(alg3.matches(getPassword2(), hashed2));
	}

	@Test
	public void hashedPasswordDataFormat() {
		String hashedPassword = alg.hash(getPassword());
		Matcher matcher = getHashRegex().matcher(hashedPassword);
		assertTrue(matcher.matches(), "Unexpected hashed password data: " + hashedPassword);
	}


}