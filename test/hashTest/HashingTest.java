package hashTest;

import static org.junit.Assert.*;

import hash.Hashing;
import hash.HashingImpl;

import java.io.FileInputStream;
import java.security.MessageDigest;


import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;


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
        assertEquals("a484381dd25c096c2ef70fe3c50f4f56", hash.toHex(hashValue));
    }
    

    
    @Test
    public void testSha1() throws Exception {
        HashingImpl hash = new HashingImpl();
        byte[] hashValue = hash.sha1("res/teste.txt");
        assertEquals("9d2eb1a653753c0eb5ed66f741a8eeba73645353", hash.toHex(hashValue));
    }

}