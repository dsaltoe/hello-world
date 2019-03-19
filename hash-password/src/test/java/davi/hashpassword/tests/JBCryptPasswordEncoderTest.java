package davi.hashpassword.tests;

import davi.hashpassword.KeyStretchingPasswordManager;

import davi.hashpassword.base.AbstractKeyStretchingTest;
import davi.hashpassword.bcrypt.JBCryptPasswordEncoder;

import java.util.regex.Pattern;

public class JBCryptPasswordEncoderTest extends AbstractKeyStretchingTest {

	@Override
	protected KeyStretchingPasswordManager createAlg(Integer rounds) {
		return new JBCryptPasswordEncoder(rounds);
	}

	@Override
	protected Integer getDefaultRounds() {
		return 12;
	}

	@Override
	protected Pattern getHashRegex() {
		// Examples:
        // ------------------------------
        // SALT                         |
        // ------------------------------
        // $2a$11$lw27.WF3yC06eDo3vE2IT.
		// $2a$12$II7qngXYw75StAYaLWdx7u3mjs8JpbiHKlh1mGkI/ZBVE9P3AaUHK
		// $2a$12$ybG4IsD.KcjKPSkpmV61RumLmHTZHDjPCvMZjUAcsoIDDxh5EpYqO
		// $2a$12$KPK3NKKJl.D6L73pvi3mOehhSHw8gSd/SVSrlqubO17jHFYldU9vu
		// $2a$12$3gFCgGysMCFSgF6zlMh1NuZuAzCqKDbeZlOMJm5Flh3GmHhpAVtIK
		// $2a$12$CBBx.Hqu1S37ZhUjFBLFwul2wy1RCV.pUPGSp8XUwWqHq1zOB7cXO
		// $2a$12$5pBcwFoUwX0mCRR1bnSd7OcCWj8xdNJvCwMEhNVpgNgjZFUiPsQai
		// $2a$12$MftLt1eCU4LB1tHFP5/Eb.4X2S1U4eiZm3BKCHKpY91PPQsZUxkFi
		// $2a$12$usFj.52jm1YhTxpRIsyLrOD4xYrAwimrlGdbqEin01R2OwEaB0QQm

		return Pattern.compile("^\\$(\\w+)\\$(\\d+)\\$(.+)$");
	}

}
