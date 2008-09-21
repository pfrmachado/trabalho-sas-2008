package assinaturas.lixo;

public interface AssinaturaDigital2 {
	byte[] recuperaStringAssinada(byte[] chavePublica, String algoritmoChave, byte[] textoAssinado, String algoritmoAssinatura);
	Boolean verificaAssinatura(byte[] chavePublica, String algoritmoChave, byte[] textoOriginal, byte[] textoAssinado, String algoritmoAssinatura);
	void recuperaArquivoAssinado(byte[] chavePublica,String algoritmoChave, String arquivoAssinado, String arquivoRecuperado, String algoritmoAssinatura);
	
}
