package br.ufsc.labsec.pbad.hiring.criptografia.certificado;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Date;

import static br.ufsc.labsec.pbad.hiring.Constantes.algoritmoAssinatura;
import static br.ufsc.labsec.pbad.hiring.Constantes.formatoCertificado;

/**
 * Classe responsável por gerar certificados no padrão X.509.
 * <p>
 * Um certificado é basicamente composto por três partes, que são:
 * <ul>
 * <li>
 * Estrutura de informações do certificado;
 * </li>
 * <li>
 * Algoritmo de assinatura;
 * </li>
 * <li>
 * Valor da assinatura.
 * </li>
 * </ul>
 */

public class GeradorDeCertificados {

    /**
     * Gera a estrutura de informações de um certificado.
     *
     * @param chavePublica  chave pública do titular.
     * @param numeroDeSerie número de série do certificado.
     * @param nome          nome do titular.
     * @param nomeAc        nome da autoridade emissora.
     * @param dias          a partir da data atual, quantos dias de validade
     *                      terá o certificado.
     * @return Estrutura de informações do certificado.
     */
    public TBSCertificate gerarEstruturaCertificado(PublicKey chavePublica,
                                                    int numeroDeSerie, String nome,
                                                    String nomeAc, int dias) throws IOException {
        AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find(algoritmoAssinatura);
        long start = System.currentTimeMillis();
        long end = start + 1000L * 60 * 60 * 24 * dias;

        V3TBSCertificateGenerator certGen = new V3TBSCertificateGenerator();
        certGen.setStartDate(new Time(new Date((start))));
        certGen.setEndDate(new Time(new Date((end))));
        certGen.setSubject(new X509Name(nome));
        certGen.setIssuer(new X509Name(nomeAc));
        certGen.setSerialNumber(new ASN1Integer(BigInteger.valueOf(numeroDeSerie)));
        certGen.setSignature(sigAlgId);
        certGen.setSubjectPublicKeyInfo(new SubjectPublicKeyInfo((ASN1Sequence)new ASN1InputStream(
                new ByteArrayInputStream(chavePublica.getEncoded())).readObject()));

        return certGen.generateTBSCertificate();
    }

    /**
     * Gera valor da assinatura do certificado.
     *
     * @param estruturaCertificado estrutura de informações do certificado.
     * @param chavePrivadaAc       chave privada da AC que emitirá esse
     *                             certificado.
     * @return Bytes da assinatura.
     */
    public DERBitString geraValorDaAssinaturaCertificado(TBSCertificate estruturaCertificado,
                                                         PrivateKey chavePrivadaAc) throws NoSuchAlgorithmException,
                                                                                    InvalidKeyException,
                                                                                    IOException,
                                                                                    SignatureException {
        Signature s = Signature.getInstance(algoritmoAssinatura);
        s.initSign(chavePrivadaAc);
        s.update(estruturaCertificado.getEncoded());
        return new DERBitString(s.sign());
    }

    /**
     * Gera um certificado.
     *
     * @param estruturaCertificado  estrutura de informações do certificado.
     * @param algoritmoDeAssinatura algoritmo de assinatura.
     * @param valorDaAssinatura     valor da assinatura.
     * @return Objeto que representa o certificado.
     * @see ASN1EncodableVector
     */
    public X509Certificate gerarCertificado(TBSCertificate estruturaCertificado,
                                            AlgorithmIdentifier algoritmoDeAssinatura,
                                            DERBitString valorDaAssinatura) throws IOException,
            CertificateException {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(estruturaCertificado);
        v.add(algoritmoDeAssinatura);
        v.add(valorDaAssinatura);

        DERSequence derSequence = new DERSequence(v);
        ByteArrayInputStream b = new ByteArrayInputStream(derSequence.getEncoded());
        return (X509Certificate) CertificateFactory.getInstance(formatoCertificado).generateCertificate(b);
    }

}
