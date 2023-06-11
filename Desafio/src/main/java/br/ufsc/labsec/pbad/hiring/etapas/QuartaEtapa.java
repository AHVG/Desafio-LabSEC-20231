package br.ufsc.labsec.pbad.hiring.etapas;

import br.ufsc.labsec.pbad.hiring.criptografia.certificado.LeitorDeCertificados;
import br.ufsc.labsec.pbad.hiring.criptografia.chave.LeitorDeChaves;
import br.ufsc.labsec.pbad.hiring.criptografia.repositorio.GeradorDeRepositorios;
import br.ufsc.labsec.pbad.hiring.criptografia.repositorio.RepositorioChaves;

import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

import static br.ufsc.labsec.pbad.hiring.Constantes.*;

/**
 * <b>Quarta etapa - gerar repositório de chaves seguro</b>
 * <p>
 * Essa etapa tem como finalidade gerar um repositório seguro de chaves
 * assimétricas. Esse repositório deverá ser no formato PKCS#12. Note que
 * esse repositório é basicamente um tabela de espalhamento com pequenas
 * mudanças. Por exemplo, sua estrutura seria algo como {@code <Alias,
 * <Certificado, Chave Privada>>}, onde o _alias_ é um nome amigável dado a
 * uma entrada da estrutura, e o certificado e chave privada devem ser
 * correspondentes à mesma identidade. O _alias_ serve como elemento de busca
 * dessa identidade. O PKCS#12 ainda conta com uma senha, que serve para
 * cifrar a estrutura (isso é feito de modo automático).
 * <p>
 * Os pontos a serem verificados para essa etapa ser considerada concluída
 * são os seguintes:
 * <ul>
 * <li>
 * gerar um repositório para o seu certificado/chave privada com senha e
 * alias de acordo com as constantes fornecidas;
 * </li>
 * <li>
 * gerar um repositório para o certificado/chave privada da AC-Raiz com senha
 * e alias de acordo com as constantes fornecidas.
 * </li>
 * </ul>
 */
public class QuartaEtapa {

    public static void executarEtapa() {
        System.out.println("> Iniciando quarta etapa\n");
        try {
            System.out.println("    Lendo do disco o certificado e o par de chaves da Ac...");
            X509Certificate certAC = LeitorDeCertificados.lerCertificadoDoDisco(caminhoCertificadoAcRaiz);
            PrivateKey chaveAC = LeitorDeChaves.lerChavePrivadaDoDisco(caminhoChavePrivadaAc, algoritmoChave);
            System.out.println("    Leitura bem sucedida!\n");

            System.out.println("    Gerando um repositório PKCS#12 para Ac...");
            GeradorDeRepositorios.gerarPkcs12(chaveAC, certAC, caminhoPkcs12AcRaiz, aliasAc, senhaMestre);
            System.out.println("    Geração bem sucedida!\n");

            System.out.println("    Lendo do disco o certificado e o par de chaves do usuário...");
            X509Certificate certUsu = LeitorDeCertificados.lerCertificadoDoDisco(caminhoCertificadoUsuario);
            PrivateKey chaveUsu = LeitorDeChaves.lerChavePrivadaDoDisco(caminhoChavePrivadaUsuario, algoritmoChave);
            System.out.println("    Leitura bem sucedida!\n");

            System.out.println("    Gerando um repositório PKCS#12 para o usuário...");
            GeradorDeRepositorios.gerarPkcs12(chaveUsu, certUsu, caminhoPkcs12Usuario, aliasUsuario, senhaMestre);
            System.out.println("    Geração bem sucedida!\n");

        } catch (CertificateException | InvalidKeySpecException | KeyStoreException | NoSuchAlgorithmException |
                 IOException e) {
            System.out.println("    " + e);
            System.out.println("    Backtrace: " + Arrays.toString(e.getStackTrace()));
        }
        System.out.println("< Quarta etapa finalizada");
    }

}
