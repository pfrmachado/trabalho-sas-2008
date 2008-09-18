package segurancaTest;

import static org.junit.Assert.*;

import java.io.FileInputStream;
import java.security.MessageDigest;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import seguranca.Hashing;
import seguranca.HashingImpl;

/**
 *
 * @author usuario
 */
public class HashingTest {

    public HashingTest() {
    	
    }

    @BeforeClass
    public static void setUpClass() throws Exception {
    }

    @AfterClass
    public static void tearDownClass() throws Exception {
    }

    @Before
    public void setUp() {
    }

    @After
    public void tearDown() {
    }

    @Test
    public void testMd5() throws Exception {
        HashingImpl hash = new HashingImpl();
        byte[] hashValue = hash.md5("res/teste.txt");
        assertEquals("698dc19d489c4e4db73e28a713eab07b", hash.toHex(hashValue));
    }
    

    
    @Test
    public void testSha1() throws Exception {
        HashingImpl hash = new HashingImpl();
        byte[] hashValue = hash.sha1("res/teste.txt");
        assertEquals("2e6f9b0d5885b6010f9167787445617f553a735f", hash.toHex(hashValue));
    }

}