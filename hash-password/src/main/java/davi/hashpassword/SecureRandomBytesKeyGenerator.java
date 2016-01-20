package davi.hashpassword;

import java.security.SecureRandom;

public final class SecureRandomBytesKeyGenerator {

	private final SecureRandom random;

	private final int keyLength;

	/**
	 * Creates a secure random key generator using the defaults.
	 */
	public SecureRandomBytesKeyGenerator() {
		this(DEFAULT_KEY_LENGTH);
	}

	/**
	 * Creates a secure random key generator with a custom key length.
	 */
	public SecureRandomBytesKeyGenerator(int keyLength) {
		this.random = new SecureRandom();
		this.keyLength = keyLength;
	}

	public int getKeyLength() {
		return keyLength;
	}

	public byte[] generateKey() {
		byte[] bytes = new byte[keyLength];
		random.nextBytes(bytes);
		return bytes;
	}
	
	public String generateKeyAsHex() {
		return CryptUtils.toHex(generateKey());
	}

	private static final int DEFAULT_KEY_LENGTH = 8;

}
