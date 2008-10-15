package simplesasTest;

import static org.junit.Assert.*;

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

import org.junit.Test;

import assinaturas.AssinaturaDigitalImpl;

import repositorio.RepositorioImpl;
import simplesas.FacadeSimpleSAS;

public class FacadeSimpleSASTest {

	
	@Test
	public void testAssinaString() {
		FacadeSimpleSAS facade = new FacadeSimpleSAS("res/sas.jks", "sas", "JCEKS",  "sas123");
		Signature sig=null;

		byte[] mensagem = "teste123".getBytes();
		try {
			sig = Signature.getInstance( "MD5withRSA" );

			sig.initVerify(facade.getPublicKey("sas"));
			sig.update(mensagem);
			
			
			assertTrue(sig.verify(facade.assinaString("sas", "sas123", mensagem, "MD5WithRSA")));

		} catch (Exception e) {
			fail("Nao foi possivel Assinar string!");
			e.printStackTrace();
		}

	}

	@Test
	public void testVerificaAssinaturaCertStringByteArrayByteArrayString() {

		FacadeSimpleSAS facade = new FacadeSimpleSAS("res/sas.jks", "sas", "JCEKS",  "sas123");
		Signature sig=null;

		byte[] mensagem = "teste123".getBytes();
		try {
			sig = Signature.getInstance( "MD5withRSA" );
			byte[] stringAssinada = facade.assinaString("sas", "sas123", mensagem, "MD5WithRSA");
			
			assertTrue(facade.verificaAssinaturaCert("sas", stringAssinada, mensagem, "MD5WithRSA"));

		} catch (Exception e) {
			fail("Erro ao verificar assinatura da string!");
			e.printStackTrace();
		}
		
	}

	@Test
	public void testVerificaAssinaturaPubkStringByteArrayByteArrayString() {
		FacadeSimpleSAS facade = new FacadeSimpleSAS("res/sas.jks", "sas", "JCEKS",  "sas123");
		Signature sig=null;

		byte[] mensagem = "teste123".getBytes();
		try {
			sig = Signature.getInstance( "MD5withRSA" );
			byte[] stringAssinada = facade.assinaString("sas", "sas123", mensagem, "MD5WithRSA");
			
			assertTrue(facade.verificaAssinaturaPubk("sas", stringAssinada, mensagem, "MD5WithRSA"));

		} catch (Exception e) {
			fail("Erro ao verificar assinatura");
			e.printStackTrace();
		}
		
	}

	@Test
	public void testVerificaAssinaturaCertStringStringStringString() {
		FacadeSimpleSAS facade = new FacadeSimpleSAS("res/sas.jks", "sas", "JCEKS",  "sas123");
		try {
			 facade.assinaArquivo("sas", "sas123", "res/testeassinadofacade.txt", "res/teste.txt", "MD5WithRSA");
			
			assertTrue(facade.verificaAssinaturaCert("sas", "res/testeassinadofacade.txt","res/teste.txt",  "MD5WithRSA"));

		} catch (Exception e) {
			fail("Erro ao verificar assinatura");
			e.printStackTrace();
		}
	}

	@Test
	public void testVerificaAssinaturaPubkStringStringStringString() {
		FacadeSimpleSAS facade = new FacadeSimpleSAS("res/sas.jks", "sas", "JCEKS",  "sas123");
		try {
			 facade.assinaArquivo("sas", "sas123", "res/testeassinadofacade.txt", "res/teste.txt", "MD5WithRSA");
			
			assertTrue(facade.verificaAssinaturaPubk("sas", "res/testeassinadofacade.txt","res/teste.txt",  "MD5WithRSA"));

		} catch (Exception e) {
			fail("Erro ao verificar assinatura ");
			e.printStackTrace();
		}
	}

	@Test
	public void testAssinaArquivo() {
		FacadeSimpleSAS facade = new FacadeSimpleSAS("res/sas.jks", "sas", "JCEKS",  "sas123");
		try {
			 facade.assinaArquivo("sas", "sas123", "res/testeassinadofacade.txt", "res/teste.txt", "MD5WithRSA");
			
			assertTrue(facade.verificaAssinaturaCert("sas", "res/testeassinadofacade.txt","res/teste.txt",  "MD5WithRSA"));

		} catch (Exception e) {
			fail("Erro ao assinar arquivo!");
			e.printStackTrace();
		}
	}

	@Test
	public void testValidaCertificado() {
		FacadeSimpleSAS facade = new FacadeSimpleSAS("res/sas.jks", "sas", "JCEKS",  "sas123");
		try {
			 facade.assinaArquivo("sas", "sas123", "res/testeassinadofacade.txt", "res/teste.txt", "MD5WithRSA");
				//Como foi gerado um certificado auto-assinado através
				//da ferramenta keytool, isto é, a chave pública do certificado
				//assinou o próprio certificado, a validação do certificado com
				//sua chave pública deve retornar "true".
				assertTrue(facade.validaCertificado("sas", "sas"));

		} catch (Exception e) {
			fail("Erro ao Validar certificado!");
			e.printStackTrace();
		}

	}

	@Test
	public void testMd5String() {
		FacadeSimpleSAS facade = new FacadeSimpleSAS();
        byte[] hashValue = facade.md5("res/teste.txt");
        assertEquals("09151a42659cfc08aff86820f973f640", toHex(hashValue));
	}

	@Test
	public void testSha1String() {
		FacadeSimpleSAS facade = new FacadeSimpleSAS();

		byte[] hashValue = facade.sha1("res/teste.txt");
        assertEquals("a1a8d617f884f106ccdcc6470c29cbdc4d9f7990", toHex(hashValue));
	}

	@Test
	public void testMd5ByteArray() {
		FacadeSimpleSAS facade = new FacadeSimpleSAS();

		byte[] hashValue = facade.sha1("teste1234".getBytes());
        assertEquals("a1a8d617f884f106ccdcc6470c29cbdc4d9f7990", toHex(hashValue));
	}

	@Test
	public void testSha1ByteArray() {
		FacadeSimpleSAS facade = new FacadeSimpleSAS();
		byte[] hashValue = facade.sha1("teste1234".getBytes());
        assertEquals("a1a8d617f884f106ccdcc6470c29cbdc4d9f7990", toHex(hashValue));
	}

	@Test
	public void testCriptografaRsaStringByteArray() {
		FacadeSimpleSAS facade = new FacadeSimpleSAS("res/sas.jks", "sas", "JCEKS",  "sas123");

		byte[] mensagem = "teste123".getBytes();
		try {
			byte[] criptografada = facade.criptografaRsa("sas", mensagem);
			assertEquals(toHex(mensagem), toHex(facade.descriptografaRsa("sas", "sas123", criptografada)));
		} catch (Exception e) {
			fail("Nao foi possivel Criptografar string!");
			e.printStackTrace();
		}
	}

	@Test
	public void testCriptografaDesStringStringByteArray() {
		FacadeSimpleSAS facade = new FacadeSimpleSAS("res/sas.jks", "sas", "JCEKS",  "sas123");

		byte[] mensagem = "teste123".getBytes();
		try {
			//chave simetrica do banco ("novachave")
			byte[] criptografada = facade.criptografaDes("novachave", "sas123", mensagem);
			assertEquals(toHex(mensagem), toHex(facade.descriptografaDes("novachave", "sas123", criptografada)));
		} catch (Exception e) {
			fail("Nao foi possivel Criptografar string!");
			e.printStackTrace();
		}
	}

	@Test
	public void testCriptografaRsaStringStringString() {
		FacadeSimpleSAS facade = new FacadeSimpleSAS("res/sas.jks", "sas", "JCEKS",  "sas123");

		try {
			facade.criptografaRsa("sas", "res/teste.txt", "res/facadetestrsa.txt" );
			facade.descriptografaRsa("sas","sas123" , "res/facadetestrsa.txt", "res/descfacadetestrsa.txt" );
			assertEquals(toHex(facade.md5("res/teste.txt")), toHex(facade.md5("res/descfacadetestrsa.txt") ));
		} catch (Exception e) {
			fail("Nao foi possivel Criptografar");
			e.printStackTrace();
		}
	}

	@Test
	public void testCriptografaDesStringStringStringString() {
		FacadeSimpleSAS facade = new FacadeSimpleSAS("res/sas.jks", "sas", "JCEKS",  "sas123");

		try {
			//chave simetrica do banco ("novachave")
			facade.criptografaDes("novachave", "sas123", "res/teste.txt", "res/facadetestdes.txt" );
			facade.descriptografaDes("novachave","sas123" , "res/facadetestdes.txt", "res/descfacadetestdes.txt" );
			assertEquals(toHex(facade.md5("res/teste.txt")), toHex(facade.md5("res/descfacadetestdes.txt") ));
		} catch (Exception e) {
			fail("Nao foi possivel Criptografar");
			e.printStackTrace();
		}
	}

	@Test
	public void testDescriptografaRsaStringStringByteArray() {
		FacadeSimpleSAS facade = new FacadeSimpleSAS("res/sas.jks", "sas", "JCEKS",  "sas123");

		byte[] mensagem = "teste123".getBytes();
		try {
			byte[] criptografada = facade.criptografaRsa("sas", mensagem);
			assertEquals(toHex(mensagem), toHex(facade.descriptografaRsa("sas", "sas123", criptografada)));
		} catch (Exception e) {
			fail("Nao foi possivel descriptografar string!");
			e.printStackTrace();
		}
	}

	@Test
	public void testDescriptografaDesStringStringByteArray() {
		FacadeSimpleSAS facade = new FacadeSimpleSAS("res/sas.jks", "sas", "JCEKS",  "sas123");
		byte[] mensagem = "teste123".getBytes();
		try {
			//chave simetrica do banco ("novachave")
			byte[] criptografada = facade.criptografaDes("novachave", "sas123", mensagem);
			assertEquals(toHex(mensagem), toHex(facade.descriptografaDes("novachave", "sas123", criptografada)));
		} catch (Exception e) {
			fail("Nao foi possivel descriptografar string!");
			e.printStackTrace();
		}
	}

	@Test
	public void testDescriptografaRsaStringStringStringString() {
		FacadeSimpleSAS facade = new FacadeSimpleSAS("res/sas.jks", "sas", "JCEKS",  "sas123");

		try {
			facade.criptografaRsa("sas", "res/teste.txt", "res/facadetestrsa.txt" );
			facade.descriptografaRsa("sas","sas123" , "res/facadetestrsa.txt", "res/descfacadetestrsa.txt" );
			assertEquals(toHex(facade.md5("res/teste.txt")), toHex(facade.md5("res/descfacadetestrsa.txt") ));
		} catch (Exception e) {
			fail("Nao foi possivel descriptografar");
			e.printStackTrace();
		}
	}

	@Test
	public void testDescriptografaDesStringStringStringString() {
		FacadeSimpleSAS facade = new FacadeSimpleSAS("res/sas.jks", "sas", "JCEKS",  "sas123");

		try {
			//chave simetrica do banco ("novachave")
			facade.criptografaDes("novachave", "sas123", "res/teste.txt", "res/facadetestdes.txt" );
			facade.descriptografaDes("novachave","sas123" , "res/facadetestdes.txt", "res/descfacadetestdes.txt" );
			assertEquals(toHex(facade.md5("res/teste.txt")), toHex(facade.md5("res/descfacadetestdes.txt") ));
		} catch (Exception e) {
			fail("Nao foi possivel descriptografar");
			e.printStackTrace();
		}
	}

	
	
	
	
	
	
	

	
	
	
	
	
	
	@Test
	public void testGetCertificate() {
		try {
			FacadeSimpleSAS facade = new FacadeSimpleSAS("res/sas.jks", "sas", "JCEKS",  "sas123");
			assertEquals("3082022930820192a003020102020448d383c7300d06092a864886f70d01010505003059310b3009060355040613024252310b300906035504081302474f310e300c06035504071305474f414953310c300a060355040a1303494e463111300f060355040b1308544f5049434f5332310c300a06035504031303534153301e170d3038303931393130343934335a170d3038313231383130343934335a3059310b3009060355040613024252310b300906035504081302474f310e300c06035504071305474f414953310c300a060355040a1303494e463111300f060355040b1308544f5049434f5332310c300a0603550403130353415330819f300d06092a864886f70d010101050003818d003081890281810091a23cb94b8c98643e46aebfe479cf91230c4705c317f5fe461109e224930b060b9f628c2085eb5689de25aef1898a416723f515a087d5b3f3b4718d206cd271322a399d1f673f57e432a14a3c64534c384a9a9a03ce262018c3b0efc7f6da185e0a3a72b377f0568d7bdef0b1e587e4aa10225e43f2efa958e4f9519d6e550f0203010001300d06092a864886f70d0101050500038181000db283cfb21c49e9f48324d5b4fab9d1236711425c38dda45b04a0cd17602e455a66bc3d3ed3bbd07d647d8a63bf8782335fc6626ea09781f118b631930e75f888677060227fefb4dccac1e0d0d2d726cfa0c6ae043ac03df686bb776852a15d26608de98887769fe8d658c5c9c4e6dec5a89c04b6cec886a5b51c1120d29145", toHex(facade.getCertificate("sas").getEncoded()));
			
		} catch (Exception e) {
			fail("Nao foi possivel obter um certificado do repositorio");
			e.printStackTrace();
		}
		
	}

	@Test
	public void testGetPrivateKey() {
		try {
			FacadeSimpleSAS facade = new FacadeSimpleSAS("res/sas.jks", "sas", "JCEKS",  "sas123");
			facade.getPrivateKey("sas", "sas123");
			assertEquals("30820277020100300d06092a864886f70d0101010500048202613082025d0201000281810091a23cb94b8c98643e46aebfe479cf91230c4705c317f5fe461109e224930b060b9f628c2085eb5689de25aef1898a416723f515a087d5b3f3b4718d206cd271322a399d1f673f57e432a14a3c64534c384a9a9a03ce262018c3b0efc7f6da185e0a3a72b377f0568d7bdef0b1e587e4aa10225e43f2efa958e4f9519d6e550f020301000102818057c15e3bfdb55bc2d3effdaf2dfae4c3bd4dd1a23c3c3d041aae7bb92476e2a6a2ec4912cd2a4574612156adc36830c256674970ddc9dc51526202269b4a57c7e6ded0b58722dba71e38bed177dcb93d2f82171f2a1c1eb90dabe4d7839a6b63c38c1a77ac8ac7682a93e821f64cc849ecef28bf759278fede2f703e885143a9024100eab86ffb4645413a6d23d46967f562d227946296b823071545a4df9fcc58a51387e7fcf4b8e8ab09ad534d5dd73f46c1edf8b6a28bde75402c6f9047cf51c12d0241009ed635e9db4ef337db294b426cff5cb232e4655e84032c8b4fc271ff6c0ea55bf7cfa7376ab2828572cabae1842cb786fc284a5333268739796e02d0ec92fcab02410099cbec241b3139c24ccd135b55b0e5e589e5a28bdb6fa82e7a09c43572b20ac8375efcd2656e9ed3a26c58df4a30bdee483d957e0063ed33f569cc82210812a9024066eefd1b634363bd13eb4bd96d5783d3fbc525a83db6ecdc0f413cad4172b058cc5ca6c9f3fc6137682fd732247cf226a92cd715d9f522f6ed298ceba6148f67024100b3e30007992782fc3d5db9e8d4558a0df48099a68416b154ee8a8d59a9020ab349fcee6c97f22a5c2161c80c402ce6e7aa7f7ccf4d83eb856914494416aaf11f",toHex(facade.getPrivateKey("sas", "sas123").getEncoded()) );
		} catch (Exception e) {
			e.printStackTrace();
		}
		
	}

	
	@Test
	public void testGetSecretKey() {
		try {
			FacadeSimpleSAS facade = new FacadeSimpleSAS("res/sas.jks", "sas", "JCEKS",  "sas123");
			facade.getSecretKey("novachave", "sas123");
			
			assertEquals("13abda3e3d10f113",toHex(facade.getSecretKey("novachave", "sas123").getEncoded()));
		} catch (Exception e) {
			e.printStackTrace();
		}
		
	}

	
	@Test
	public void testGetPublicKey() {
		try {
			FacadeSimpleSAS facade = new FacadeSimpleSAS("res/sas.jks", "sas", "JCEKS",  "sas123");
			assertEquals("30819f300d06092a864886f70d010101050003818d003081890281810091a23cb94b8c98643e46aebfe479cf91230c4705c317f5fe461109e224930b060b9f628c2085eb5689de25aef1898a416723f515a087d5b3f3b4718d206cd271322a399d1f673f57e432a14a3c64534c384a9a9a03ce262018c3b0efc7f6da185e0a3a72b377f0568d7bdef0b1e587e4aa10225e43f2efa958e4f9519d6e550f0203010001", toHex(facade.getPublicKey("sas").getEncoded()));
			
		} catch (Exception e) {
			fail("Nao foi possivel obter um certificado do repositorio");
			e.printStackTrace();
		}

	}

	@Test
	public void testGetKeyPair() {
		try {
			KeyPair kp;
			FacadeSimpleSAS facade = new FacadeSimpleSAS("res/sas.jks", "sas", "JCEKS",  "sas123");
			
			kp =facade.getKeyPair("sas", "sas123"); 

			assertEquals("30820277020100300d06092a864886f70d0101010500048202613082025d0201000281810091a23cb94b8c98643e46aebfe479cf91230c4705c317f5fe461109e224930b060b9f628c2085eb5689de25aef1898a416723f515a087d5b3f3b4718d206cd271322a399d1f673f57e432a14a3c64534c384a9a9a03ce262018c3b0efc7f6da185e0a3a72b377f0568d7bdef0b1e587e4aa10225e43f2efa958e4f9519d6e550f020301000102818057c15e3bfdb55bc2d3effdaf2dfae4c3bd4dd1a23c3c3d041aae7bb92476e2a6a2ec4912cd2a4574612156adc36830c256674970ddc9dc51526202269b4a57c7e6ded0b58722dba71e38bed177dcb93d2f82171f2a1c1eb90dabe4d7839a6b63c38c1a77ac8ac7682a93e821f64cc849ecef28bf759278fede2f703e885143a9024100eab86ffb4645413a6d23d46967f562d227946296b823071545a4df9fcc58a51387e7fcf4b8e8ab09ad534d5dd73f46c1edf8b6a28bde75402c6f9047cf51c12d0241009ed635e9db4ef337db294b426cff5cb232e4655e84032c8b4fc271ff6c0ea55bf7cfa7376ab2828572cabae1842cb786fc284a5333268739796e02d0ec92fcab02410099cbec241b3139c24ccd135b55b0e5e589e5a28bdb6fa82e7a09c43572b20ac8375efcd2656e9ed3a26c58df4a30bdee483d957e0063ed33f569cc82210812a9024066eefd1b634363bd13eb4bd96d5783d3fbc525a83db6ecdc0f413cad4172b058cc5ca6c9f3fc6137682fd732247cf226a92cd715d9f522f6ed298ceba6148f67024100b3e30007992782fc3d5db9e8d4558a0df48099a68416b154ee8a8d59a9020ab349fcee6c97f22a5c2161c80c402ce6e7aa7f7ccf4d83eb856914494416aaf11f",toHex(kp.getPrivate().getEncoded()) );
			assertEquals("30819f300d06092a864886f70d010101050003818d003081890281810091a23cb94b8c98643e46aebfe479cf91230c4705c317f5fe461109e224930b060b9f628c2085eb5689de25aef1898a416723f515a087d5b3f3b4718d206cd271322a399d1f673f57e432a14a3c64534c384a9a9a03ce262018c3b0efc7f6da185e0a3a72b377f0568d7bdef0b1e587e4aa10225e43f2efa958e4f9519d6e550f0203010001", toHex(kp.getPublic().getEncoded()));

		} catch (Exception e) {
			fail("Not yet implemented");
			e.printStackTrace();
		}

	}

	
	
	
	
	
    private String toHex(byte[] hash) {
        final char[] HEX_CHARS = {'0', '1', '2', '3', '4', '5',
            '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
        };

        char strHash[] = new char[hash.length * 2];
        for (int i = 0, x = 0; i < hash.length; i++) {
            strHash[x++] = HEX_CHARS[(hash[i] >>> 4) & 0xf];
            strHash[x++] = HEX_CHARS[hash[i] & 0xf];
        }
        return new String(strHash);
    }

}
