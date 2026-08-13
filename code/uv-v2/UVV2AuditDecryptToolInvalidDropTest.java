package ee.ivxv.audit.tools;

import ee.ivxv.audit.AuditContext;
import ee.ivxv.common.cli.CommonArgs;
import ee.ivxv.common.cli.InitialContext;
import ee.ivxv.common.conf.Conf;
import ee.ivxv.common.conf.LocaleConf;
import ee.ivxv.common.crypto.Plaintext;
import ee.ivxv.common.crypto.elgamal.ElGamalCiphertext;
import ee.ivxv.common.crypto.elgamal.ElGamalDecryptionProof;
import ee.ivxv.common.crypto.elgamal.ElGamalParameters;
import ee.ivxv.common.crypto.elgamal.ElGamalPrivateKey;
import ee.ivxv.common.crypto.elgamal.ElGamalPublicKey;
import ee.ivxv.common.model.AnonymousBallotBox;
import ee.ivxv.common.model.Proof;
import ee.ivxv.common.service.console.Console;
import ee.ivxv.common.service.console.Progress;
import ee.ivxv.common.service.i18n.I18n;
import ee.ivxv.common.util.Json;
import ee.ivxv.common.util.Util;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import org.junit.Test;

public class UVV2AuditDecryptToolInvalidDropTest {
    private static final String ELECTION = "uv-v2";
    private static final String DISTRICT = "10.1";
    private static final String STATION = "001";
    private static final String QUESTION = "Q1";
    private static final String PARTY = "party";
    private static final String CANDIDATE = "1001";
    private static final String CANDIDATE_NAME = "Candidate";

    @Test
    public void acceptsValidBallotMarkedInvalidWithoutInvalidityProofs() throws Exception {
        FixturePaths fixture = fixture("out-valid-drop");
        RecordingConsole console = new RecordingConsole();

        DecryptTool tool = new DecryptTool(new AuditContext(
                new InitialContext("uv-v2", new LocaleConf(), console, new SimpleI18n()),
                new Conf(),
                new CommonArgs()));

        tool.run(createArgs(fixture, false));

        assertOutputContains(console.lines, "m_decrypt_bb_has_invalids m_yes");
        assertOutputContains(console.lines, "m_decrypt_consistent_valids m_yes");
        assertOutputContains(console.lines, "m_tally_match m_yes");
        assertOutputContains(console.lines, "m_decrypt_success");
        System.out.println(
                "PASS: DecryptTool accepted the dropped valid ballot without invalidity proofs.");
    }

    @Test
    public void rejectsSameFixtureWhenInvalidityProofsAreProvided() throws Exception {
        FixturePaths fixture = fixture("out-invalidity-proof");
        RecordingConsole console = new RecordingConsole();

        DecryptTool tool = new DecryptTool(new AuditContext(
                new InitialContext("uv-v2", new LocaleConf(), console, new SimpleI18n()),
                new Conf(),
                new CommonArgs()));

        tool.run(createArgs(fixture, true));

        assertOutputContains(console.lines, "m_decrypt_verified_invalid m_no");
        assertOutputContains(console.lines, "m_decrypt_failure");
        System.out.println(
                "PASS: DecryptTool rejected the same output when invalidity proofs were supplied.");
    }

    private static DecryptTool.DecryptArgs createArgs(FixturePaths fixture, boolean withInvalidProofs)
            throws Exception {
        DecryptTool.DecryptArgs args = new DecryptTool.DecryptArgs();
        args.inputPath.parse(List.of(fixture.validProofs.toString()));
        args.pubPath.parse(List.of(fixture.publicKey.toString()));
        args.discardedInputPath.parse(List.of(fixture.discarded.toString()));
        args.anonBoxPath.parse(List.of(fixture.anonBox.toString()));
        args.plainBoxPath.parse(List.of(fixture.plainBox.toString()));
        args.tallyPath.parse(List.of(fixture.tally.toString()));
        args.districts.parse(List.of(fixture.districts.toString()));
        args.candidates.parse(List.of(fixture.candidates.toString()));
        args.outputPath.parse(List.of(fixture.out.toString()));
        if (withInvalidProofs) {
            args.invalidInputPath.parse(List.of(fixture.invalidProofs.toString()));
        }
        return args;
    }

    private static FixturePaths fixture(String outputName) throws Exception {
        Path pocRoot = Path.of(System.getenv("IVXV_POCROOT"));
        Path dir = pocRoot.resolve("uv-v2");
        Files.createDirectories(dir);
        Path out = dir.resolve(outputName);
        deleteIfExists(out);

        Path publicKey = dir.resolve("pub.pem");
        Path anonBox = dir.resolve("anon-bb.json");
        Path validProofs = dir.resolve("valid-proofs.json");
        Path invalidProofs = dir.resolve("invalid-proofs.json");
        Path discarded = dir.resolve("discarded.json");
        Path plainBox = dir.resolve("plain-bb.json");
        Path tally = dir.resolve("tally.json");
        Path districts = dir.resolve("districts.json");
        Path candidates = dir.resolve("candidates.json");

        if (!allExist(publicKey, anonBox, validProofs, invalidProofs, discarded, plainBox, tally,
                districts, candidates)) {
            writeFixture(pocRoot, publicKey, anonBox, validProofs, invalidProofs, discarded,
                    plainBox, tally, districts, candidates);
        }

        return new FixturePaths(publicKey, anonBox, validProofs, invalidProofs, discarded, plainBox,
                tally, districts, candidates, out);
    }

    private static void writeFixture(Path pocRoot, Path publicKey, Path anonBox, Path validProofs,
            Path invalidProofs, Path discarded, Path plainBox, Path tally, Path districts,
            Path candidates) throws Exception {
        ElGamalPublicKey base = new ElGamalPublicKey(
                pocRoot.resolve("p-v1").resolve("modp3072-public.pem"));
        ElGamalParameters params = base.getParameters();
        ElGamalPrivateKey sk = new ElGamalPrivateKey(params, BigInteger.ONE);
        ElGamalPublicKey pk = sk.getPublicKey();
        ElGamalCiphertext ciphertext = pk.encrypt(new Plaintext(CANDIDATE), BigInteger.ONE);
        ElGamalDecryptionProof proof = sk.provableDecrypt(ciphertext);

        Files.writeString(publicKey, Util.encodePublicKey(pk.getBytes()), StandardCharsets.UTF_8);

        Proof proofs = new Proof(ELECTION);
        Json.write(proofs, validProofs);

        Proof invalid = new Proof(ELECTION);
        invalid.addProof(proof);
        Json.write(invalid, invalidProofs);

        Json.write(createAnonymousBallotBox(ciphertext.getBytes()), anonBox);
        Json.write(createDiscarded(ciphertext.getBytes()), discarded);
        Json.write(createPlainBallotBox(), plainBox);
        Json.write(createTally(), tally);
        Json.write(createDistrictList(), districts);
        Json.write(createCandidateList(), candidates);
    }

    private static boolean allExist(Path... paths) {
        return java.util.Arrays.stream(paths).allMatch(Files::exists);
    }

    private static void deleteIfExists(Path path) throws Exception {
        if (!Files.exists(path)) {
            return;
        }
        try (var paths = Files.walk(path)) {
            for (Path p : paths.sorted(Comparator.reverseOrder()).collect(Collectors.toList())) {
                Files.delete(p);
            }
        }
    }

    private static AnonymousBallotBox createAnonymousBallotBox(byte[] ciphertext) {
        Map<String, Map<String, Map<String, List<byte[]>>>> districts = new LinkedHashMap<>();
        Map<String, Map<String, List<byte[]>>> stations = new LinkedHashMap<>();
        Map<String, List<byte[]>> questions = new LinkedHashMap<>();
        questions.put(QUESTION, new ArrayList<>(List.of(ciphertext)));
        stations.put(STATION, questions);
        districts.put(DISTRICT, stations);
        return new AnonymousBallotBox(ELECTION, districts);
    }

    private static Map<String, Object> createDiscarded(byte[] ciphertext) {
        return Map.of(
                "election", ELECTION,
                "invalid", List.of(Map.of(
                        "district", DISTRICT,
                        "station", STATION,
                        "question", QUESTION,
                        "vote", ciphertext)));
    }

    private static Map<String, Object> createPlainBallotBox() {
        return Map.of(
                "election", ELECTION,
                "byparish", Map.of(DISTRICT, Map.of(STATION, List.of("invalid"))),
                "bydistrict", Map.of(DISTRICT, List.of("invalid")));
    }

    private static Map<String, Object> createTally() {
        Map<String, Integer> stationCounts = new LinkedHashMap<>();
        stationCounts.put(CANDIDATE, 0);
        stationCounts.put("invalid", 1);

        Map<String, Map<String, Integer>> districtByParish = new LinkedHashMap<>();
        districtByParish.put(STATION, stationCounts);

        Map<String, Integer> districtCounts = new LinkedHashMap<>();
        districtCounts.put(CANDIDATE, 0);
        districtCounts.put("invalid", 1);

        return Map.of(
                "election", ELECTION,
                "byparish", Map.of(DISTRICT, districtByParish),
                "bydistrict", Map.of(DISTRICT, districtCounts));
    }

    private static Map<String, Object> createCandidateList() {
        Map<String, Map<String, Map<String, String>>> choices = new LinkedHashMap<>();
        Map<String, Map<String, String>> parties = new LinkedHashMap<>();
        Map<String, String> candidates = new LinkedHashMap<>();
        candidates.put(CANDIDATE, CANDIDATE_NAME);
        parties.put(PARTY, candidates);
        choices.put(DISTRICT, parties);
        return Map.of(
                "election", ELECTION,
                "choices", choices);
    }

    private static Map<String, Object> createDistrictList() {
        return Map.of(
                "election", ELECTION,
                "districts", Map.of(DISTRICT, Map.of(
                        "name", "District",
                        "parish", List.of(STATION))),
                "regions", Map.of(STATION, Map.of(
                        "county", "County",
                        "parish", "Parish",
                        "state", "State")),
                "counties", Map.of("County", List.of(STATION)));
    }

    private static void assertOutputContains(List<String> lines, String expected) {
        boolean present = lines.stream().anyMatch(line -> line.contains(expected));
        if (!present) {
            throw new IllegalStateException(
                    "Expected DecryptTool output line missing: " + expected + "\nActual output:\n"
                            + lines.stream().collect(Collectors.joining("\n")));
        }
    }

    private record FixturePaths(
            Path publicKey,
            Path anonBox,
            Path validProofs,
            Path invalidProofs,
            Path discarded,
            Path plainBox,
            Path tally,
            Path districts,
            Path candidates,
            Path out) {
    }

    private static final class SimpleI18n implements I18n {
        @Override
        public String get(Enum<?> key, Object... args) {
            if (args == null || args.length == 0) {
                return key.name();
            }
            return key.name() + " " + java.util.Arrays.stream(args)
                    .map(arg -> arg instanceof Enum<?> e ? e.name() : String.valueOf(arg))
                    .collect(Collectors.joining(" "));
        }

        @Override
        public String format(Instant i) {
            return i.toString();
        }
    }

    private static final class RecordingConsole implements Console {
        private final List<String> lines = new ArrayList<>();

        @Override
        public void println() {
            lines.add("");
        }

        @Override
        public void println(String format, Object... args) {
            String line = args == null || args.length == 0 ? format : String.format(format, args);
            lines.add(line);
        }

        @Override
        public void printlnraw(String format, Object... args) {
            println(format, args);
        }

        @Override
        public String readln() {
            throw new UnsupportedOperationException();
        }

        @Override
        public String readPw() {
            throw new UnsupportedOperationException();
        }

        @Override
        public Progress startProgress(String format, long total) {
            return new NoOpProgress();
        }

        @Override
        public Progress startInfiniteProgress(String format, long total) {
            return new NoOpProgress();
        }

        @Override
        public void shutdown() {
        }
    }

    private static final class NoOpProgress implements Progress {
        @Override
        public void increase(int amount) {
        }

        @Override
        public void finish() {
        }
    }
}
