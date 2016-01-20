package davi.hashpassword.pbkdf2.impl;

import static davi.hashpassword.CryptUtils.fromHex;
import static davi.hashpassword.CryptUtils.toHex;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import davi.hashpassword.CryptUtils;
import davi.hashpassword.KeyStretchingPasswordEncoder;
import davi.hashpassword.SecureRandomBytesKeyGenerator;

public class PBKDF2PasswordEncoder2 implements KeyStretchingPasswordEncoder {
	public static final String PBKDF2_ALGORITHM = "PBKDF2WithHmacSHA512";

	// The following constants may be changed without breaking existing hashes.
	public static final int SALT_BYTE_SIZE = 24;
	public static final int DEFAULT_HASH_BYTE_SIZE = 64; // 512 bits
	public static final int DEFAULT_PBKDF2_ITERATIONS = 1000;

	public static final int ITERATION_INDEX = 0;
	public static final int SALT_INDEX = 1;
	public static final int PBKDF2_INDEX = 2;

	private final int iterations;
	private final int hashByteSize;

	public PBKDF2PasswordEncoder2() {
		this(DEFAULT_PBKDF2_ITERATIONS);
	}

	public PBKDF2PasswordEncoder2(int iterations) {
		this(iterations, DEFAULT_HASH_BYTE_SIZE);
	}

	public PBKDF2PasswordEncoder2(int iterations, int hashByteSize) {
		if (iterations <= 0) {
			throw new IllegalArgumentException("Invalid value for iterations: " + iterations);
		}
		if (hashByteSize < 16) {
			throw new IllegalArgumentException("Invalid value for hash byte size: " + hashByteSize);
		}

		this.iterations = iterations;
		this.hashByteSize = hashByteSize;
	}

	private String encode(String password, byte[] salt) {
		byte[] hash = pbkdf2(password.toCharArray(), salt, iterations, hashByteSize);
		
		// format iterations:salt:hash
		return iterations + ":" + toHex(salt) + ":" + toHex(hash);
	}

	private static byte[] pbkdf2(char[] password, byte[] salt, int iterations, int bytes) {
		PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, bytes * 8);
		try {
			SecretKeyFactory skf = SecretKeyFactory.getInstance(PBKDF2_ALGORITHM);
			return skf.generateSecret(spec).getEncoded();
		} catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
			throw new RuntimeException(e);
		}
	}
	
	@Override
	public String encode(String password) {
		byte[] salt = getSecureRandom().generateKey();
		return encode(password, salt);
	}

	@Override
	public String encode(String password, String salt) {
		byte[] saltAsBytes = CryptUtils.fromHex(salt);
		return encode(password, saltAsBytes);
	}

	@Override
	public boolean matches(String password, String encodedPassword) {
		// Decode the hash into its parameters
		String[] params = encodedPassword.split(":");
		int iterations = Integer.parseInt(params[ITERATION_INDEX]);
		byte[] salt = fromHex(params[SALT_INDEX]);
		byte[] hash = fromHex(params[PBKDF2_INDEX]);
		
		// Compute the hash of the provided password, using the same salt, iteration count, and hash length
		byte[] testHash = pbkdf2(password.toCharArray(), salt, iterations, hash.length);
		
		// Compare the hashes in constant time. The password is correct if both hashes match.
		return CryptUtils.slowEquals(hash, testHash);
	}
	
	@Override
	public String genSalt() {
		return getSecureRandom().generateKeyAsHex();
	}

	private SecureRandomBytesKeyGenerator getSecureRandom() {
		return new SecureRandomBytesKeyGenerator(SALT_BYTE_SIZE);
	}

}