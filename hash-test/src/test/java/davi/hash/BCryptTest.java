package davi.hash;

import static org.junit.Assert.*;

import org.junit.Before;
import org.junit.Test;
import org.mindrot.jbcrypt.BCrypt;

public class BCryptTest extends CryptTest {

	private static final String SALT_11 = "$2a$11$lw27.WF3yC06eDo3vE2IT.";
	
	@Before
	public void before() {
		alg = new BCryptAlgorithm(12);
	}
	
	@Test
	public void testDiferentesSALTs_e_fatores_Mesmo_Hash() {
		String hashed = BCrypt.hashpw(getPassword(), BCrypt.gensalt());
		String hashed12 = BCrypt.hashpw(getPassword(), BCrypt.gensalt(12));
		
		assertTrue(BCrypt.checkpw(getPassword(), hashed));
		assertTrue(BCrypt.checkpw(getPassword(), hashed12));

		assertNotEquals(hashed, hashed12);
	}

	@Test
	public void testDiferentesSALTs_Mesmo_Hash2() {
		String salt_10 = BCrypt.gensalt();
		String salt_10_2 = BCrypt.gensalt();
		String salt_11 = BCrypt.gensalt(11);
		String salt_11_2 = BCrypt.gensalt(11);
		
		assertNotEquals(salt_10, salt_10_2);
		assertNotEquals(salt_11, salt_11_2);
		assertNotEquals(salt_10, salt_11);
		
		String hashed_10 = BCrypt.hashpw(getPassword(), salt_10);
		String hashed_10_2 = BCrypt.hashpw(getPassword(), salt_10_2);
		String hashed_11 = BCrypt.hashpw(getPassword(), salt_11);
		String hashed_11_2 = BCrypt.hashpw(getPassword(), salt_11_2);
		
		assertNotEquals(hashed_10, hashed_10_2);
		assertNotEquals(hashed_11, hashed_11_2);
		assertNotEquals(hashed_10, hashed_11);
		
		assertTrue(BCrypt.checkpw(getPassword(), hashed_10));
		assertTrue(BCrypt.checkpw(getPassword(), hashed_10_2));
		assertTrue(BCrypt.checkpw(getPassword(), hashed_11));
		assertTrue(BCrypt.checkpw(getPassword(), hashed_11_2));
	}
}
