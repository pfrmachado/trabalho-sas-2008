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
        assertEquals("09151a42659cfc08aff86820f973f640", hash.toHex(hashValue));
    }
    

    
    @Test
    public void testSha1() throws Exception {
        HashingImpl hash = new HashingImpl();
        byte[] hashValue = hash.sha1("res/teste.txt");
        assertEquals("a1a8d617f884f106ccdcc6470c29cbdc4d9f7990", hash.toHex(hashValue));
    }

}