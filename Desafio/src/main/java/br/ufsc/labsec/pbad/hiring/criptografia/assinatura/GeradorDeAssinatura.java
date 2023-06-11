package br.ufsc.labsec.pbad.hiring.criptografia.assinatura;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Store;

import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import static br.ufsc.labsec.pbad.hiring.Constantes.algoritmoAssinatura;
import static java.util.GregorianCalendar.BC;

/**
 * Classe responsável por gerar uma assinatura digital.
 * <p>
 * Aqui será necessário usar a biblioteca Bouncy Castle, pois ela já possui a
 * estrutura básica da assinatura implementada.
 */
public class GeradorDeAssinatura {

    private X509Certificate certificado;
    private PrivateKey chavePrivada;
    private CMSSignedDataGenerator geradorAssinaturaCms;

    /**
     * Construtor.
     */
    public GeradorDeAssinatura() {
        this.certificado = null;
        this.chavePrivada = null;
        this.geradorAssinaturaCms = null;
    }

    /**
     * Informa qual será o assinante.
     *
     * @param certificado  certificado, no padrão X.509, do assinante.
     * @param chavePrivada chave privada do assinante.
     */
    public void informaAssinante(X509Certificate certificado,
                                 PrivateKey chavePrivada) {
        this.certificado = certificado;
        this.chavePrivada = chavePrivada;
    }

    /**
     * Gera uma assinatura no padrão CMS.
     *
     * @param caminhoDocumento caminho do documento que será assinado.
     * @return Documento assinado.
     */
    public CMSSignedData assinar(String caminhoDocumento) throws OperatorCreationException,
            CMSException, CertificateEncodingException, IOException {
        CMSTypedData doc = preparaDadosParaAssinar(caminhoDocumento);
        SignerInfoGenerator estrutura = preparaInformacoesAssinante(this.chavePrivada, this.certificado);
        this.geradorAssinaturaCms = new CMSSignedDataGenerator();
        Store certs = new JcaCertStore(Arrays.asList(this.certificado));

        this.geradorAssinaturaCms.addSignerInfoGenerator(estrutura);
        this.geradorAssinaturaCms.addCertificates(certs);

        // o segundo parametro do método generate do geradorAssinaturaCms é true,
        // pois o conteúdo está junto com a assinatura
        CMSSignedData documentoAssinado = this.geradorAssinaturaCms.generate(doc, true);
        return documentoAssinado;
    }

    /**
     * Transforma o documento que será assinado para um formato compatível
     * com a assinatura.
     *
     * @param caminhoDocumento caminho do documento que será assinado.
     * @return Documento no formato correto.
     */
    private CMSTypedData preparaDadosParaAssinar(String caminhoDocumento) {
        File arquivo = new File(caminhoDocumento);
        CMSTypedData doc = new CMSProcessableFile(arquivo);
        return doc;
    }

    /**
     * Gera as informações do assinante na estrutura necessária para ser
     * adicionada na assinatura.
     *
     * @param chavePrivada chave privada do assinante.
     * @param certificado  certificado do assinante.
     * @return Estrutura com informações do assinante.
     */
    private SignerInfoGenerator preparaInformacoesAssinante(PrivateKey chavePrivada,
                                                            Certificate certificado) throws OperatorCreationException,
            CertificateEncodingException, IOException {
        ContentSigner sha1Signer = new JcaContentSignerBuilder(algoritmoAssinatura).build(chavePrivada);
        DigestCalculatorProvider dcp = new JcaDigestCalculatorProviderBuilder().build();
        SignerInfoGenerator sig = new JcaSignerInfoGeneratorBuilder(dcp).build(sha1Signer, new X509CertificateHolder(certificado.getEncoded()));
        return sig;
    }

    /**
     * Escreve a assinatura no local apontado.
     *
     * @param arquivo    arquivo que será escrita a assinatura.
     * @param assinatura objeto da assinatura.
     */
    public void escreveAssinatura(OutputStream arquivo, CMSSignedData assinatura) throws IOException {
        arquivo.write(assinatura.getEncoded());
    }

}
