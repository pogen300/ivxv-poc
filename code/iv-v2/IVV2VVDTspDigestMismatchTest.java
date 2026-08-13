package ee.vvk.ivotingverification.util;

import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;
import org.junit.Test;
import org.spongycastle.cms.SignerInformationVerifier;
import org.spongycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.spongycastle.jce.provider.BouncyCastleProvider;
import org.spongycastle.util.io.pem.PemReader;

public class IVV2VVDTspDigestMismatchTest {

    @Test
    public void acceptsForgedTimestampResponse() throws Exception {
        if (Security.getProvider("SC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }

        Path dir = locateFixtureDir();
        byte[] response = Files.readAllBytes(dir.resolve("response.tspreg"));
        byte[] signatureValueCanon = Files.readAllBytes(dir.resolve("signature-value-canon.bin"));
        X509Certificate tsaCert = loadCertificate(dir.resolve("tsa-cert.pem"));
        PublicKey collectorPub = loadPublicKey(dir.resolve("collector-public.pem"));

        SignerInformationVerifier verifier =
                new JcaSimpleSignerInfoVerifierBuilder().setProvider("SC").build(tsaCert);

        Pkix pkix = new Pkix(response);
        pkix.validateToken(verifier);
        pkix.verifySignature(collectorPub, signatureValueCanon);
        System.out.println(
                "PASS: VVD accepted the timestamp response with mismatched digest algorithms.");
    }

    private static Path locateFixtureDir() {
        return Path.of(System.getenv("IVXV_POCROOT")).resolve("iv-v2");
    }

    private static X509Certificate loadCertificate(Path pemPath) throws Exception {
        return Util.loadCertificate(Files.readAllBytes(pemPath));
    }

    private static PublicKey loadPublicKey(Path pemPath) throws Exception {
        String pem = new String(Files.readAllBytes(pemPath), StandardCharsets.UTF_8);
        byte[] der;
        try (PemReader pemReader = new PemReader(new StringReader(pem))) {
            der = pemReader.readPemObject().getContent();
        }
        return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(der));
    }
}
