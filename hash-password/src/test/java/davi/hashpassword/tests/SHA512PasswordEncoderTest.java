package davi.hashpassword.tests;

import org.junit.jupiter.api.BeforeEach;

import davi.hashpassword.base.AbstractHashFunctionTest;
import davi.hashpassword.sha512.SHA512PasswordEncoder;

public class SHA512PasswordEncoderTest extends AbstractHashFunctionTest {

	@BeforeEach
	public void before() {
		alg = new SHA512PasswordEncoder();
	}
	
}
