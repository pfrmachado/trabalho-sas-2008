package assinaturas;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;

public interface AssinaturaDigital {
 byte[] assinaString(PrivateKey privk, byte[] stringOriginal, String algoritmoAssinatura);
 boolean verificaAssinatura(PublicKey pubk, byte[] stringAssinada, byte[] stringOriginal, String algoritmoAssinatura);
 boolean verificaAssinatura(PublicKey chavePublica, String arquivoAssinado, String arquivoOriginal, String algoritmoAssinatura);
 boolean verificaAssinatura(Certificate cert, byte[] stringAssinada, byte[] stringOriginal, String algoritmoAssinatura);
 boolean verificaAssinatura(Certificate cert, String arquivoAssinado, String arquivoOriginal, String algoritmoAssinatura);
 void assinaArquivo(PrivateKey chavePrivada, String arquivoaAssinar, String arquivoOriginal, String algoritmoAssinatura);
}
