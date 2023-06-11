package br.ufsc.labsec.pbad.hiring.criptografia.repositorio;

import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import static br.ufsc.labsec.pbad.hiring.Constantes.formatoRepositorio;

/**
 * Classe responsável por gerar um repositório de chaves PKCS#12.
 *
 * @see KeyStore
 */
public class GeradorDeRepositorios {

    /**
     * Gera um PKCS#12 para a chave privada/certificado passados como parâmetro.
     *
     * @param chavePrivada  chave privada do titular do certificado.
     * @param certificado   certificado do titular.
     * @param caminhoPkcs12 caminho onde será escrito o PKCS#12.
     * @param alias         nome amigável dado à entrada do PKCS#12, que
     *                      comportará a chave e o certificado.
     * @param senha         senha de acesso ao PKCS#12.
     */
    public static void gerarPkcs12(PrivateKey chavePrivada, X509Certificate certificado,
                                   String caminhoPkcs12, String alias, char[] senha) throws IOException,
            KeyStoreException, CertificateException, NoSuchAlgorithmException {
        KeyStore pkcs12 = KeyStore.getInstance(formatoRepositorio);
        pkcs12.load(null, null);
        pkcs12.setKeyEntry(alias, chavePrivada, senha, new X509Certificate[] {certificado});
        pkcs12.store(new FileOutputStream(caminhoPkcs12), senha);
    }

}
