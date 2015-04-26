package davi.hash;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;

import org.junit.Test;
import org.mindrot.jbcrypt.BCrypt;

public abstract class AbstractHashTest {

	protected HashAlgorithm alg;

	public AbstractHashTest() {
		super();
	}

	@Test
	public void mesmo_salt_gera_dois_hashes_iguais() {
		String salt = alg.genSalt();
		
		String hashed1 = alg.hash(getPassword(), salt);
		String hashed2 = alg.hash(getPassword(), salt);
		
		assertEquals(hashed1, hashed2);
	
		assertTrue(alg.check(getPassword(), hashed1));
		assertTrue(alg.check(getPassword(), hashed2));
	}

	@Test
	public void test_gensalt_dinamico() {
		String salt1 = alg.genSalt();
		String salt2 = alg.genSalt();
		
		assertNotEquals(salt1, salt2);
		
		String hashed1 = alg.hash(getPassword(), salt1);
		String hashed2 = alg.hash(getPassword(), salt2);
		
		assertNotEquals(hashed1, hashed2);
	
		assertTrue(alg.check(getPassword(), hashed1));
		assertTrue(alg.check(getPassword(), hashed2));
	}

	protected String getPassword() {
		return new String("fklbnaslbnaflbnvxm)-0*%");
	}

	@Test
	public void testDiferentesSALTs_Mesmo_Hash() {
		String hashed = BCrypt.hashpw(getPassword(), BCrypt.gensalt());
		String hashed12 = BCrypt.hashpw(getPassword(), BCrypt.gensalt(12));
		
		assertTrue(BCrypt.checkpw(getPassword(), hashed));
		assertTrue(BCrypt.checkpw(getPassword(), hashed12));
	
		assertNotEquals(hashed, hashed12);
	}

}