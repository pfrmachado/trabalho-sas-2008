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
        assertEquals("1ca308df6cdb0a8bf40d59be2a17eac1", hash.toHex(hashValue));
//    	assertEquals("1ca308df6cdb0a8bf40d59be2a17eac1", Seguranca.md5("nomearquivo.txt"));
    }
    

    
    @Test
    public void testSha1() throws Exception {
        HashingImpl hash = new HashingImpl();
        byte[] hashValue = hash.sha1("res/teste.txt");
        assertEquals("9dc628289966d144c1a5fa20dd60b1ca1b9de6ed", hash.toHex(hashValue));
    }

}