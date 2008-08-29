package br.ufg.inf.seguranca;

/**
 * Serviços de hashing da biblioteca.
 * 
 * @author Fábio Nogueira de Lucena
 * @version 0.1
 */
public interface Hashing {
    byte[] md5(String nomeArquivo);
    byte[] sha1(String nomeArquivo);
    byte[] md5(byte[] entrada);
    byte[] sha1(byte[] entrada);
}
