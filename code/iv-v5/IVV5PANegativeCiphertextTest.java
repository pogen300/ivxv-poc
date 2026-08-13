package ee.ivxv.common.crypto;

import static org.junit.Assert.assertEquals;

import ee.ivxv.common.crypto.elgamal.ElGamalParameters;
import ee.ivxv.common.crypto.elgamal.ElGamalPublicKey;
import ee.ivxv.common.math.ModPGroup;
import ee.ivxv.common.math.ModPGroupElement;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import org.junit.Test;

public class IVV5PANegativeCiphertextTest {

    private static final String RFC3526_MODP_3072_P =
            "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08"
            + "8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B"
            + "302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9"
            + "A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE6"
            + "49286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8"
            + "FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D"
            + "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C"
            + "180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718"
            + "3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D"
            + "04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7D"
            + "B3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D226"
            + "1AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200C"
            + "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFC"
            + "E0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF";

    @Test
    public void rejectsNegativeAsn1Ciphertext() throws Exception {
        BigInteger p = new BigInteger(RFC3526_MODP_3072_P, 16);
        ModPGroup group = new ModPGroup(p);
        ModPGroupElement generator = new ModPGroupElement(group, BigInteger.valueOf(4));

        ElGamalParameters params = new ElGamalParameters(group, generator, "TEST");
        ElGamalPublicKey pk = new ElGamalPublicKey(params, generator);
        byte[] ciphertext = Base64.getDecoder().decode(Files.readString(locateFixture()).trim());

        CorrectnessUtil.CiphertextCorrectness result =
                CorrectnessUtil.isValidCiphertext(pk, ciphertext);
        assertEquals(CorrectnessUtil.CiphertextCorrectness.INVALID_RANGE, result);
        System.out.println("PASS: PA rejected the negative ASN.1 ciphertext as INVALID_RANGE.");
    }

    private static Path locateFixture() {
        return Path.of(System.getenv("IVXV_POCROOT")).resolve("iv-v5/negative_modp3072_ciphertext.b64");
    }
}
