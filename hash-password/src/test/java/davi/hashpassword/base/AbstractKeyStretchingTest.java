package davi.hashpassword.base;

import static davi.hashpassword.base.TestUtils.getPassword;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import davi.hashpassword.KeyStretchingPasswordEncoder;

public abstract class AbstractKeyStretchingTest extends AbstractPasswordEncoderTest<KeyStretchingPasswordEncoder> {

	@Test
	public void differentHashsForEqualPasswordsTest() {
		String hashed1 = alg.encode(getPassword());
		String hashed2 = alg.encode(getPassword());

		assertNotEquals(hashed1, hashed2);
		
		assertTrue(alg.matches(getPassword(), hashed1));
		assertTrue(alg.matches(getPassword(), hashed2));
	}

	@Override
	@Test
	public void sameHashForEqualPasswordsTest() {
		String salt = alg.genSalt();
		String hashed1 = alg.encode(getPassword(), salt);
		String hashed2 = alg.encode(getPassword(), salt);
		
		assertEquals(hashed1, hashed2);
	
		assertTrue(alg.matches(getPassword(), hashed1));
		assertTrue(alg.matches(getPassword(), hashed2));
	}

	@Test
	public abstract void differentHashsForSamePasswordWithDifferentRoundsTest();
	
	@Test
	public void mesmo_salt_gera_dois_hashes_iguais() {
		String salt = alg.genSalt();
		
		String hashed1 = alg.encode(getPassword(), salt);
		String hashed2 = alg.encode(getPassword(), salt);
		
		assertEquals(hashed1, hashed2);
	
		assertTrue(alg.matches(getPassword(), hashed1));
		assertTrue(alg.matches(getPassword(), hashed2));
	}

	@Test
	public void test_gensalt_dinamico() {
		String salt1 = alg.genSalt();
		String salt2 = alg.genSalt();
		
		assertNotEquals(salt1, salt2);
		
		String hashed1 = alg.encode(getPassword(), salt1);
		String hashed2 = alg.encode(getPassword(), salt2);
		
		assertNotEquals(hashed1, hashed2);
	
		assertTrue(alg.matches(getPassword(), hashed1));
		assertTrue(alg.matches(getPassword(), hashed2));
	}

}