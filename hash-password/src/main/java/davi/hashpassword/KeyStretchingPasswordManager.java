package davi.hashpassword;

public interface KeyStretchingPasswordManager {

	String hash(String password, String salt);
	
	String hash(String password);

	boolean matches(String password, String hashedPasswordData);

	String genSalt();

}
