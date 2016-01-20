package davi.hashpassword.tests;

import org.junit.Before;

import davi.hashpassword.base.AbstractHashFunctionTest;
import davi.hashpassword.sha512.SHA512PasswordEncoder;

public class SHA512PasswordEncoderTest extends AbstractHashFunctionTest {

	@Before
	public void before() {
		alg = new SHA512PasswordEncoder();
	}
	
}
