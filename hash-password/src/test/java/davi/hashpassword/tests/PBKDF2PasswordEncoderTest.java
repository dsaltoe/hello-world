package davi.hashpassword.tests;

import static davi.hashpassword.base.TestUtils.getPassword;
import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import davi.hashpassword.KeyStretchingPasswordManager;
import davi.hashpassword.base.AbstractKeyStretchingTest;
import davi.hashpassword.pbkdf2.impl.PBKDF2PasswordEncoder2;

public class PBKDF2PasswordEncoderTest extends AbstractKeyStretchingTest {

	@Override
	protected KeyStretchingPasswordManager createAlg(Integer rounds) {
		return 	new PBKDF2PasswordEncoder2(rounds);
	}

	@Override
	protected Integer getDefaultRounds() {
		return 10000;
	}

	@Override
	protected Pattern getHashRegex() {
		//1000:3e004efa1a1c28392bd4db83df72027fe16343580180d890:d3d76858fa9163c113840784b46bb6dee09b44bd373c9cc442c86f28688b3a78aa93fc8ee2f8f489d2fed972eecffb37071025bf70de23a8b91989f89d9f5aeb
		return Pattern.compile("^(\\d+):([a-fA-F\\d]+):([a-fA-F\\d]+)$");
	}

	@Test
	public void hashedPasswordDataFormatPBKDF2() {
		String genSalt = alg.genSalt();
		String hashedPassword = alg.hash(getPassword(), genSalt);
		Matcher matcher = getHashRegex().matcher(hashedPassword);
		assertTrue(matcher.matches(), "Unexpected hashed password data: " + hashedPassword);
		
		String rounds = matcher.group(1);
		String salt = matcher.group(2);
		String hashedKey = matcher.group(3);
		
		System.out.println(rounds);
		System.out.println(salt);
		System.out.println(hashedKey);

		assertEquals(getDefaultRounds().toString(), rounds);
		assertEquals(genSalt, salt);
		assertEquals(24 * 2, salt.length());
		assertEquals(64 * 2, hashedKey.length());
	}

}
