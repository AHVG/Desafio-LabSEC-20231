package br.ufsc.labsec.pbad.hiring.etapas;

import br.ufsc.labsec.pbad.hiring.criptografia.assinatura.VerificadorDeAssinatura;
import br.ufsc.labsec.pbad.hiring.criptografia.certificado.GeradorDeCertificados;
import br.ufsc.labsec.pbad.hiring.criptografia.chave.GeradorDeChaves;
import br.ufsc.labsec.pbad.hiring.criptografia.repositorio.RepositorioChaves;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.x509.TBSCertificate;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.encoders.Base64;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import static br.ufsc.labsec.pbad.hiring.Constantes.*;

/**
 * <b>Sexta etapa - verificar uma assinatura digital</b>
 * <p>
 * Por último, será necessário verificar a integridade da assinatura
 * recém gerada. Note que o processo de validação de uma assinatura
 * digital pode ser muito complexo, mas aqui o desafio será simples. Para
 * verificar a assinatura será necessário apenas decifrar o valor da
 * assinatura (resultante do processo de cifra do resumo criptográfico do
 * arquivo {@code textoPlano.txt} com as informações da estrutura da
 * assinatura) e comparar esse valor com o valor do resumo criptográfico do
 * arquivo assinado. Como dito na fundamentação, para assinar é usada a chave
 * privada, e para decifrar (verificar) é usada a chave pública.
 * <p>
 * Os pontos a serem verificados para essa etapa ser considerada concluída
 * são os seguintes:
 * <ul>
 * <li>
 * verificar a assinatura gerada na etapa anterior, de acordo com o
 * processo descrito, e apresentar esse resultado.
 * </li>
 * </ul>
 */
public class SextaEtapa {

    public static void executarEtapa() {
        System.out.println("> Iniciando sexta etapa\n");
        try {

            System.out.println("    Lendo certificado usuário do PKCS#12...");
            RepositorioChaves repo = new RepositorioChaves(senhaMestre, aliasUsuario);
            repo.abrir(caminhoPkcs12Usuario);
            X509Certificate certificado = repo.pegarCertificado();
            System.out.println("    Leitura bem sucedida!\n");

            System.out.println("    Lendo assinatura no disco...");
            CMSSignedData documentoAssinado = new CMSSignedData(Files.readAllBytes(Path.of(caminhoAssinatura)));
            System.out.println("    Leitura bem sucedida!\n");

            System.out.println("    Gerando um certificado falso para teste...");
            GeradorDeChaves gdc = new GeradorDeChaves(algoritmoChave);
            KeyPair parChave = gdc.gerarParDeChaves(256);
            GeradorDeCertificados gerador = new GeradorDeCertificados();
            TBSCertificate estruturaFake = gerador.gerarEstruturaCertificado(parChave.getPublic(),
                    numeroDeSerie, nomeUsuario, nomeUsuario, 2);
            DERBitString assinaturaFake = gerador.geraValorDaAssinaturaCertificado(estruturaFake, parChave.getPrivate());
            X509Certificate certificadoFake = gerador.gerarCertificado(estruturaFake, estruturaFake.getSignature(), assinaturaFake);
            System.out.println("    Geração bem sucedida!\n");

            System.out.println("    Verificando...");
            VerificadorDeAssinatura verificadorDeAssinatura = new VerificadorDeAssinatura();

            boolean assinaturaValida = verificadorDeAssinatura.verificarAssinatura(certificado, documentoAssinado);
            System.out.println("    <Teste certificado original> Assinatura válida: " + assinaturaValida);
            assinaturaValida = verificadorDeAssinatura.verificarAssinatura(certificadoFake, documentoAssinado);
            System.out.println("    <Teste certificado falso>    Assinatura válida: " + assinaturaValida);
            System.out.println("    Verificação bem sucedida!\n");

        } catch (CertificateException | IOException | KeyStoreException | NoSuchAlgorithmException | CMSException |
                 OperatorCreationException | InvalidKeyException | SignatureException e) {
            System.out.println("    " + e);
            System.out.println("    Backtrace: " + Arrays.toString(e.getStackTrace()));
        }
        System.out.println("< Sexta etapa finalizada");
    }

}
