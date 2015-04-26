package davi.hash;

public abstract class HashAlgorithm {

	public abstract String genSalt();

	public abstract String hash(String password, String salt);

	public abstract boolean check(String password, String hashed1);

}
