package br.ufsc.labsec.pbad.hiring.criptografia.repositorio;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import static br.ufsc.labsec.pbad.hiring.Constantes.formatoRepositorio;


/**
 * Essa classe representa um repositório de chaves do tipo PKCS#12.
 *
 * @see KeyStore
 */
public class RepositorioChaves {

    private KeyStore repositorio;
    private char[] senha;
    private String alias;

    /**
     * Construtor.
     */
    public RepositorioChaves(char[] s, String a) throws KeyStoreException {
        repositorio = KeyStore.getInstance(formatoRepositorio);
        senha = s;
        alias = a;
    }

    /**
     * Abre o repositório do local indicado.
     *
     * @param caminhoRepositorio caminho do PKCS#12.
     */
    public void abrir(String caminhoRepositorio) throws IOException, CertificateException, NoSuchAlgorithmException {
        repositorio.load(new FileInputStream(caminhoRepositorio), senha);
    }

    /**
     * Obtém a chave privada do PKCS#12.
     *
     * @return Chave privada.
     */
    public PrivateKey pegarChavePrivada() throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException {
        return (PrivateKey) repositorio.getKey(alias, senha);
    }

    /**
     * Obtém do certificado do PKCS#12.
     *
     * @return Certificado.
     */
    public X509Certificate pegarCertificado() throws KeyStoreException {
        return (X509Certificate) repositorio.getCertificate(alias);
    }

}
