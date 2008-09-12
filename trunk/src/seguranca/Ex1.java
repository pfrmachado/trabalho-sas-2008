package seguranca;


import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;
 
public class Ex1 {
 
	public static void main(String[] args) throws IOException {
		BufferedReader userInput = new BufferedReader (new InputStreamReader(System.in));
 
		System.out.println("Enter string:");
		String rawString = userInput.readLine();
 
		try {
			System.out.println("SHA1 hash of string: " + AeSimpleSHA1.SHA1(rawString));
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
}
