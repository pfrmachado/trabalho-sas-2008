package assinaturas.lixo;

import static org.junit.Assert.assertEquals;

import org.junit.Test;



public class AssinaturaDigital2Test {
	@Test
	public void recuperaStringAssinadaTest() throws Exception{
		
		byte[] chavePublica = null;
		byte[] textoAssinado = null;
		String algoritmoChave = "RSA";
		String algoritmoAssinatura = "MD5withRSA";
		
		AssinaturaDigitalImpl2 ass = new AssinaturaDigitalImpl2();
		
		byte[] stringAssinada = null;
		
		assertEquals(stringAssinada, ass.recuperaStringAssinada(chavePublica, algoritmoChave, textoAssinado, algoritmoAssinatura));
		
	}
}
