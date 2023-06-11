package br.ufsc.labsec.pbad.hiring.criptografia.certificado;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import static br.ufsc.labsec.pbad.hiring.Constantes.formatoCertificado;

/**
 * Classe responsável por ler um certificado do disco.
 *
 * @see CertificateFactory
 */
public class LeitorDeCertificados {

    /**
     * Lê um certificado do local indicado.
     *
     * @param caminhoCertificado caminho do certificado a ser lido.
     * @return Objeto do certificado.
     */
    public static X509Certificate lerCertificadoDoDisco(String caminhoCertificado) throws IOException, CertificateException {
        File arquivo = new File(caminhoCertificado);
        byte[] certificadoBytes= Files.readAllBytes(arquivo.toPath());
        return (X509Certificate) CertificateFactory.getInstance(formatoCertificado).generateCertificate(new ByteArrayInputStream(certificadoBytes));
    }

}
