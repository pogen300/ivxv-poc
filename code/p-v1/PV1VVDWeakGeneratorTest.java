package ee.vvk.ivotingverification.common.crypto.elgamal;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import org.junit.Test;
import org.spongycastle.asn1.ASN1InputStream;
import org.spongycastle.asn1.ASN1Integer;
import org.spongycastle.asn1.ASN1Primitive;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.x509.SubjectPublicKeyInfo;

import ee.vvk.ivotingverification.common.crypto.DecrypterWithRandomness;
import ee.vvk.ivotingverification.common.crypto.x509.X509PublicKey;
import ee.vvk.ivotingverification.common.math.group.modp.ModPElement;
import ee.vvk.ivotingverification.common.math.group.modp.ModPGroup;

public class PV1VVDWeakGeneratorTest {

    @Test
    public void acceptsIdentityGeneratorParameterAndCiphertext() throws Exception {
        String pem = readFixture("weak-g1-y1-public.pem");
        SubjectPublicKeyInfo spki = parseSubjectPublicKeyInfo(pem);
        ASN1Sequence params = ASN1Sequence.getInstance(spki.getAlgorithm().getParameters());
        ModPGroup group = new ModPGroup(params.toArray());

        assertEquals(new ModPElement(group, BigInteger.ONE), group.generator());

        DecrypterWithRandomness decrypter = X509PublicKey.parseX509PEMPublicKey(pem);
        assertNotNull(decrypter);

        byte[] ciphertext = Base64.getDecoder().decode(readFixture("weak-g1-y1-ciphertext.b64").trim());
        byte[] randomness = Base64.getDecoder().decode(readFixture("weak-g1-y1-randomness.b64").trim());
        String plaintext = readFixture("weak-g1-y1-plaintext.txt").trim();
        assertEquals(plaintext, decrypter.decryptWithRandomness(ciphertext, randomness));
        System.out.println(
                "PASS: VVD accepted the identity generator and decrypted the matching ciphertext.");
    }

    @Test
    public void acceptsNonQRGeneratorParameter() throws Exception {
        String pem = readFixture("weak-nonqr-y1-public.pem");
        SubjectPublicKeyInfo spki = parseSubjectPublicKeyInfo(pem);
        ASN1Sequence params = ASN1Sequence.getInstance(spki.getAlgorithm().getParameters());
        ModPGroup group = new ModPGroup(params.toArray());
        BigInteger p = ASN1Integer.getInstance(params.getObjectAt(0)).getPositiveValue();

        assertEquals(new ModPElement(group, p.subtract(BigInteger.ONE)), group.generator());
        try {
            group.ofASN1(new ASN1Integer(p.subtract(BigInteger.ONE)).getEncoded());
            fail("expected non-QR generator encoding to be rejected as a normal group element");
        } catch (IllegalArgumentException expected) {
        }

        DecrypterWithRandomness decrypter = X509PublicKey.parseX509PEMPublicKey(pem);
        assertNotNull(decrypter);
        System.out.println("PASS: VVD parsed the public key containing a non-QR generator.");
    }

    private static SubjectPublicKeyInfo parseSubjectPublicKeyInfo(String pem) throws Exception {
        byte[] der = pemDecode(pem);
        try (ASN1InputStream input = new ASN1InputStream(der)) {
            ASN1Primitive primitive = input.readObject();
            return SubjectPublicKeyInfo.getInstance(primitive);
        }
    }

    private static byte[] pemDecode(String pem) {
        String normalized = pem
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s+", "");
        return Base64.getDecoder().decode(normalized);
    }

    private static String readFixture(String name) throws Exception {
        return new String(Files.readAllBytes(Path.of(System.getenv("IVXV_POCROOT"), "p-v1", name)),
                StandardCharsets.UTF_8);
    }
}
