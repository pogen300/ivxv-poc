package ee.ivxv.common.crypto;

import static org.junit.Assert.assertEquals;

import ee.ivxv.common.crypto.CorrectnessUtil.CiphertextCorrectness;
import ee.ivxv.common.math.Group;
import ee.ivxv.common.math.ModPGroup;
import ee.ivxv.common.math.ModPGroupElement;
import ee.ivxv.common.util.Util;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import org.junit.Test;

public class PV1PAWeakGeneratorTest {

    @Test
    public void acceptsIdentityGeneratorParameterAndCiphertext() throws Exception {
        ee.ivxv.common.crypto.elgamal.ElGamalPublicKey publicKey =
                new ee.ivxv.common.crypto.elgamal.ElGamalPublicKey(
                        Util.decodePublicKey(Files.readString(fixture("weak-g1-y1-public.pem"))));

        ModPGroupElement generator =
                (ModPGroupElement) publicKey.getParameters().getGenerator();
        assertEquals(BigInteger.ONE, generator.getValue());
        assertEquals(Group.Decodable.VALID,
                publicKey.getParameters().getGroup().isGroupElement(generator));

        byte[] ciphertext = Base64.getDecoder().decode(
                Files.readString(fixture("weak-g1-y1-ciphertext.b64"), StandardCharsets.UTF_8).trim());
        assertEquals(CiphertextCorrectness.VALID,
                CorrectnessUtil.isValidCiphertext(publicKey, ciphertext));
        System.out.println("PASS: PA accepted the identity generator and matching ciphertext.");
    }

    @Test
    public void acceptsNonQRGeneratorParameter() throws Exception {
        ee.ivxv.common.crypto.elgamal.ElGamalPublicKey publicKey =
                new ee.ivxv.common.crypto.elgamal.ElGamalPublicKey(
                        Util.decodePublicKey(Files.readString(fixture("weak-nonqr-y1-public.pem"))));

        ModPGroup group = (ModPGroup) publicKey.getParameters().getGroup();
        ModPGroupElement generator =
                (ModPGroupElement) publicKey.getParameters().getGenerator();
        BigInteger p = group.getFieldOrder();

        assertEquals(p.subtract(BigInteger.ONE), generator.getValue());
        assertEquals(Group.Decodable.INVALID_QR, group.isGroupElement(generator));
        System.out.println("PASS: PA parsed the non-QR generator parameter.");
    }

    private static Path fixture(String name) {
        return Path.of(System.getenv("IVXV_POCROOT"), "p-v1", name);
    }
}
