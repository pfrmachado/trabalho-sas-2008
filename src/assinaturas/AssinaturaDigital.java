package assinaturas;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;

/**
 * Assina digitalmente um documento (arquivo) ou sequencia de bytes, 
 * verifica a assinatura de um dado documento ou sequencia de bytes e 
 * valida um certificado digital. 
 *
 * @author Leandro Alexandre, Sérgio Daniel, Rafael Duarte, Thiago Rosa 
 * @version 0.6
 */

public interface AssinaturaDigital {
 byte[] assinaString(PrivateKey privk, byte[] stringOriginal, String algoritmoAssinatura);
 boolean verificaAssinatura(PublicKey pubk, byte[] stringAssinada, byte[] stringOriginal, String algoritmoAssinatura);
 boolean verificaAssinatura(PublicKey chavePublica, String arquivoAssinado, String arquivoOriginal, String algoritmoAssinatura);
 boolean verificaAssinatura(Certificate cert, byte[] stringAssinada, byte[] stringOriginal, String algoritmoAssinatura);
 boolean verificaAssinatura(Certificate cert, String arquivoAssinado, String arquivoOriginal, String algoritmoAssinatura);
 void assinaArquivo(PrivateKey chavePrivada, String arquivoaAssinar, String arquivoOriginal, String algoritmoAssinatura);
 boolean validaCertificado(Certificate certificado, PublicKey pubk);

}
