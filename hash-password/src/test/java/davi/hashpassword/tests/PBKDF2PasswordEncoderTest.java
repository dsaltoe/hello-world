package davi.hashpassword.tests;

import static davi.hashpassword.base.TestUtils.getPassword;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.junit.Before;
import org.junit.Test;

import davi.hashpassword.base.AbstractKeyStretchingTest;
import davi.hashpassword.pbkdf2.impl.PBKDF2PasswordEncoder2;

public class PBKDF2PasswordEncoderTest extends AbstractKeyStretchingTest {

	@Before
	public void before() {
		alg = new PBKDF2PasswordEncoder2(10000);
	}
	
	@Test
	public void testHashSize() {
		//1000:3e004efa1a1c28392bd4db83df72027fe16343580180d890:d3d76858fa9163c113840784b46bb6dee09b44bd373c9cc442c86f28688b3a78aa93fc8ee2f8f489d2fed972eecffb37071025bf70de23a8b91989f89d9f5aeb
		
		Pattern pattern = Pattern.compile("^(\\d+)\\:([a-fA-F\\d]+)\\:([a-fA-F\\d]+)$");
		
		String hashedPassword = alg.encode(getPassword());
		System.out.println(hashedPassword);
		
		Matcher matcher = pattern.matcher(hashedPassword);
		assertTrue(matcher.matches());
		
		String iterations = matcher.group(1);
		String salt = matcher.group(2);
		String hashedKey = matcher.group(3);
		
		System.out.println(iterations);
		System.out.println(salt);
		System.out.println(hashedKey);
		
		assertEquals(24 * 2, salt.length());
		assertEquals(64 * 2, hashedKey.length());
	}
}
