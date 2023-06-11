package br.ufsc.labsec.pbad.hiring.etapas;

import br.ufsc.labsec.pbad.hiring.criptografia.certificado.EscritorDeCertificados;
import br.ufsc.labsec.pbad.hiring.criptografia.certificado.GeradorDeCertificados;
import br.ufsc.labsec.pbad.hiring.criptografia.chave.GeradorDeChaves;
import br.ufsc.labsec.pbad.hiring.criptografia.chave.LeitorDeChaves;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.x509.TBSCertificate;

import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

import static br.ufsc.labsec.pbad.hiring.Constantes.*;

/**
 * <b>Terceira etapa - gerar certificados digitais</b>
 * <p>
 * Aqui você terá que gerar dois certificados digitais. A identidade ligada
 * a um dos certificados digitais deverá ser a sua. A entidade emissora do
 * seu certificado será a AC-Raiz, cuja chave privada já foi previamente
 * gerada. Também deverá ser feito o certificado digital para a AC-Raiz,
 * que deverá ser autoassinado.
 * <p>
 * Os pontos a serem verificados para essa etapa ser considerada concluída
 * são os seguintes:
 * <ul>
 * <li>
 * emitir um certificado digital autoassinado no formato X.509 para a AC-Raiz;
 * </li>
 * <li>
 * emitir um certificado digital no formato X.509, assinado pela AC-Raiz. O
 * certificado deve ter as seguintes características:
 * <ul>
 * <li>
 * {@code Subject} deverá ser o seu nome;
 * </li>
 * <li>
 * {@code SerialNumber} deverá ser o número da sua matrícula;
 * </li>
 * <li>
 * {@code Issuer} deverá ser a AC-Raiz.
 * </li>
 * </ul>
 * </li>
 * <li>
 * anexar ao desafio os certificados emitidos em formato PEM;
 * </li>
 * <li>
 * as chaves utilizadas nessa etapa deverão ser as mesmas já geradas.
 * </li>
 * </ul>
 */
public class TerceiraEtapa {

    private static boolean chaveValida(X509Certificate certificado, PublicKey chavePublica) {
        try{
            certificado.verify(chavePublica);
            return true;
        } catch (SignatureException | NoSuchProviderException | CertificateException | NoSuchAlgorithmException |
                 InvalidKeyException e) {
            return false;
        }

    }

    public static void executarEtapa() {
        System.out.println("> Iniciando terceira etapa\n");
        try {
            System.out.println("    Lendo do disco as chaves geradas na etapa anterior...");
            PrivateKey chavePrivadaUsuario = LeitorDeChaves.lerChavePrivadaDoDisco(caminhoChavePrivadaUsuario, algoritmoChave);
            PublicKey chavePublicaUsuario = LeitorDeChaves.lerChavePublicaDoDisco(caminhoChavePublicaUsuario, algoritmoChave);
            PrivateKey chavePrivadaAC = LeitorDeChaves.lerChavePrivadaDoDisco(caminhoChavePrivadaAc, algoritmoChave);
            PublicKey chavePublicaAC = LeitorDeChaves.lerChavePublicaDoDisco(caminhoChavePublicaAc, algoritmoChave);
            System.out.println("    Leitura bem sucedida!\n");

            System.out.println("    Gerando certificado autoassinado...");
            GeradorDeCertificados gerador = new GeradorDeCertificados();
            TBSCertificate estruturaUsuario = gerador.gerarEstruturaCertificado(chavePublicaUsuario,
                    numeroDeSerie, nomeUsuario, nomeUsuario, 2);
            DERBitString assinaturaUsuario = gerador.geraValorDaAssinaturaCertificado(estruturaUsuario, chavePrivadaUsuario);
            X509Certificate certificadoUsuario = gerador.gerarCertificado(estruturaUsuario, estruturaUsuario.getSignature(), assinaturaUsuario);
            System.out.println("    Geração bem sucedida!\n");

            System.out.println("    Gerando certificado emitido pela Ac...");
            TBSCertificate estruturaAC = gerador.gerarEstruturaCertificado(chavePublicaAC,
                    numeroSerieAc, nomeUsuario, nomeAcRaiz, 2);
            DERBitString assinaturaAC = gerador.geraValorDaAssinaturaCertificado(estruturaAC, chavePrivadaAC);
            X509Certificate certificadoAC = gerador.gerarCertificado(estruturaAC, estruturaAC.getSignature(), assinaturaAC);
            System.out.println("    Geração bem sucedida!\n");

            System.out.println("    Escrevendo em disco os certificados...");
            EscritorDeCertificados.escreveCertificado(caminhoCertificadoUsuario, certificadoUsuario.getEncoded());
            EscritorDeCertificados.escreveCertificado(caminhoCertificadoAcRaiz, certificadoAC.getEncoded());
            System.out.println("    Escrita bem sucedida!\n");

            GeradorDeChaves gdcFalso = new GeradorDeChaves(algoritmoChave);
            KeyPair parDeChavesFalsaUsuario = gdcFalso.gerarParDeChaves(256);
            KeyPair parDeChavesFalsaAC = gdcFalso.gerarParDeChaves(521);

            System.out.println("    Testando válida das chaves públicas...");
            System.out.println("        Testando chave Usuário...");
            System.out.println("        Chave original válida: " + chaveValida(certificadoUsuario, chavePublicaUsuario));
            System.out.println("        Chave falsa válida: " + chaveValida(certificadoUsuario, parDeChavesFalsaUsuario.getPublic()));
            System.out.println();
            System.out.println("        Testando chave AC...");
            System.out.println("        Chave original válida: " + chaveValida(certificadoAC, chavePublicaAC));
            System.out.println("        Chave falsa válida: " + chaveValida(certificadoAC, parDeChavesFalsaAC.getPublic()));
            System.out.println("    Teste bem sucedido!\n");

        } catch (InvalidKeyException | SignatureException | InvalidKeySpecException | NoSuchAlgorithmException |
                 IOException | CertificateException e) {
            System.out.println("    " + e);
            System.out.println("    Backtrace: " + Arrays.toString(e.getStackTrace()));
        }
        System.out.println("< Terceira etapa finalizada");
    }

}
