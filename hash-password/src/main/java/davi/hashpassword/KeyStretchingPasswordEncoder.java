package davi.hashpassword;

public interface KeyStretchingPasswordEncoder extends PasswordEncoder {

	String encode(String password, String salt);
	
	String genSalt();

}
