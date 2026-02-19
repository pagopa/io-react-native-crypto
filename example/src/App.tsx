import * as React from "react";

import {
  Platform,
  SafeAreaView,
  StatusBar,
  View,
  Text,
  TextInput,
  TouchableOpacity,
  ScrollView,
  StyleSheet,
} from "react-native";
import {
  CryptoError,
  deleteKey,
  ES256,
  generate,
  generateSalt,
  digest,
  hashString,
  hashBytes,
  getPublicKey,
  getPublicKeyFixed,
  isKeyStrongboxBacked,
  sign,
  verifyCertificateChain,
} from "@pagopa/io-react-native-crypto";
import {
  mockCertificateChainReal,
  mockCertNoCrl,
} from "./mocks/certifaces.mock";

// ─── Small reusable components ───────────────────────────────────────────────

function SectionHeader({ title }: { title: string }) {
  return (
    <View style={styles.sectionHeader}>
      <Text style={styles.sectionHeaderText}>{title}</Text>
      <View style={styles.sectionDivider} />
    </View>
  );
}

function Btn({
  title,
  onPress,
  variant = "default",
}: {
  title: string;
  onPress: () => void;
  variant?: "default" | "danger";
}) {
  return (
    <TouchableOpacity
      onPress={onPress}
      style={[styles.btn, variant === "danger" && styles.btnDanger]}
      activeOpacity={0.75}
    >
      <Text style={styles.btnText}>{title}</Text>
    </TouchableOpacity>
  );
}

// ─── App ─────────────────────────────────────────────────────────────────────

export default function App() {
  const [logText, setLogText] = React.useState<string | undefined>();
  const [keyTag, setKeyTag] = React.useState<string>("key");

  const log = (value: unknown) => {
    const text =
      typeof value === "string" ? value : JSON.stringify(value, null, 2);
    console.log(text);
    setLogText(text);
  };

  const logError = (reason: CryptoError | unknown) => {
    console.log(reason);
    setLogText(`Error: ${reason}`);
  };

  return (
    <SafeAreaView style={styles.safe}>
      <ScrollView contentContainerStyle={styles.container}>
        {/* ── Key tag input ── */}
        <Text style={styles.label}>Key tag</Text>
        <TextInput
          onChangeText={setKeyTag}
          defaultValue={keyTag}
          style={styles.input}
          placeholder="key tag"
          autoCapitalize="none"
          autoCorrect={false}
        />

        {/* ── Section 1: Hardware-backed keys ── */}
        <SectionHeader title="Hardware Keys" />
        <View style={styles.row}>
          <Btn
            title="Create"
            onPress={() => generate(keyTag).then(log).catch(logError)}
          />
          <Btn
            title="Get (legacy)"
            onPress={() => getPublicKey(keyTag).then(log).catch(logError)}
          />
          <Btn
            title="Get (fixed)"
            onPress={() => getPublicKeyFixed(keyTag).then(log).catch(logError)}
          />
          <Btn
            title="Sign"
            onPress={() =>
              sign("Ceci n'est pas une nonce", keyTag).then(log).catch(logError)
            }
          />
          <Btn
            title="Strongbox?"
            onPress={() =>
              isKeyStrongboxBacked(keyTag)
                .then((v) => log(v ? "Strongbox ✓" : "TEE (not Strongbox)"))
                .catch(logError)
            }
          />
          <Btn
            title="Delete"
            variant="danger"
            onPress={() =>
              deleteKey(keyTag)
                .then(() => log("Key deleted"))
                .catch(logError)
            }
          />
        </View>

        {/* ── Section 2: Certificate validation ── */}
        <SectionHeader title="Certificate Validation" />
        <View style={styles.row}>
          <Btn
            title="Verify — with CRL"
            onPress={() =>
              verifyCertificateChain(
                mockCertificateChainReal.x5c,
                mockCertificateChainReal.trustAnchorCert,
                { connectTimeout: 10000, readTimeout: 10000, requireCrl: true }
              )
                .then(log)
                .catch(logError)
            }
          />
          <Btn
            title="Verify — no CRL"
            onPress={() =>
              verifyCertificateChain(
                mockCertNoCrl.x5c,
                mockCertNoCrl.trustAnchorCert,
                { connectTimeout: 10000, readTimeout: 10000, requireCrl: false }
              )
                .then(log)
                .catch(logError)
            }
          />
        </View>

        {/* ── Section 3: Soft-crypto primitives ── */}
        <SectionHeader title="Soft Crypto" />
        <View style={styles.row}>
          <Btn
            title="generateSalt(32)"
            onPress={() =>
              generateSalt(32)
                .then((v) => log(`salt (32 chars):\n${v}`))
                .catch(logError)
            }
          />
          <Btn
            title="ES256 round-trip"
            onPress={async () => {
              try {
                const payload = "test-payload-for-es256";
                const { publicKey, privateKey } = await ES256.generateKeyPair();
                const signer = await ES256.getSigner(privateKey);
                const signature = await signer(payload);
                const verifier = await ES256.getVerifier(publicKey);
                const isValid = await verifier(payload, signature);
                log(
                  `ES256 round-trip\n\npubKey:\n${JSON.stringify(publicKey, null, 2)}\n\nsig: ${signature}\n\nvalid: ${isValid}`
                );
              } catch (e) {
                logError(e);
              }
            }}
          />
        </View>

        {/* ── Section 4: Hash methods ── */}
        <SectionHeader title="Hash" />
        <View style={styles.row}>
          <Btn
            title="hashString"
            onPress={() =>
              hashString("Hello, world!", "sha-256")
                .then((hex) => log(`hashString("Hello, world!", "sha-256"):\n${hex}`))
                .catch(logError)
            }
          />
          <Btn
            title="hashBytes"
            onPress={() => {
              // "Hello, world!" encoded as hex bytes
              const hex = Array.from(
                new TextEncoder().encode("Hello, world!"),
                (b) => b.toString(16).padStart(2, "0")
              ).join("");
              return hashBytes(hex, "sha-256")
                .then((result) =>
                  log(`hashBytes(hex("Hello, world!"), "sha-256"):\n${result}`)
                )
                .catch(logError);
            }}
          />
          <Btn
            title="digest (string)"
            onPress={() =>
              digest("Hello, world!", "sha-256")
                .then((bytes) => {
                  const hex = Array.from(bytes, (b) =>
                    b.toString(16).padStart(2, "0")
                  ).join("");
                  log(`digest("Hello, world!", "sha-256"):\n${hex}`);
                })
                .catch(logError)
            }
          />
          <Btn
            title="digest (ArrayBuffer)"
            onPress={() => {
              const buf = new TextEncoder().encode("Hello, world!").buffer;
              return digest(buf, "sha-256")
                .then((bytes) => {
                  const hex = Array.from(bytes, (b) =>
                    b.toString(16).padStart(2, "0")
                  ).join("");
                  log(`digest(ArrayBuffer("Hello, world!"), "sha-256"):\n${hex}`);
                })
                .catch(logError);
            }}
          />
          <Btn
            title="All agree?"
            onPress={async () => {
              try {
                const input = "Hello, world!";
                const alg = "sha-256";
                const hexInput = Array.from(
                  new TextEncoder().encode(input),
                  (b) => b.toString(16).padStart(2, "0")
                ).join("");
                const buf = new TextEncoder().encode(input).buffer;

                const [hs, hb, ds, db] = await Promise.all([
                  hashString(input, alg),
                  hashBytes(hexInput, alg),
                  digest(input, alg).then((u8) =>
                    Array.from(u8, (b) => b.toString(16).padStart(2, "0")).join("")
                  ),
                  digest(buf, alg).then((u8) =>
                    Array.from(u8, (b) => b.toString(16).padStart(2, "0")).join("")
                  ),
                ]);

                const allMatch = hs === hb && hb === ds && ds === db;
                log(
                  `All hash methods agree: ${allMatch ? "✓ YES" : "✗ NO"}\n\nhashString:       ${hs}\nhashBytes:        ${hb}\ndigest (string):  ${ds}\ndigest (buffer):  ${db}`
                );
              } catch (e) {
                logError(e);
              }
            }}
          />
        </View>

        {/* ── Log output ── */}
        <SectionHeader title="Output" />
        <View style={styles.logBox}>
          <ScrollView>
            <Text style={styles.logText} selectable>
              {logText ?? "—"}
            </Text>
          </ScrollView>
        </View>
      </ScrollView>
    </SafeAreaView>
  );
}

// ─── Styles ───────────────────────────────────────────────────────────────────

const styles = StyleSheet.create({
  safe: {
    flex: 1,
    backgroundColor: "#F5F5F5",
    paddingTop: Platform.OS === "android" ? StatusBar.currentHeight : 0,
  },
  container: {
    padding: 16,
    paddingBottom: 32,
  },
  label: {
    fontSize: 12,
    fontWeight: "600",
    color: "#555",
    marginBottom: 4,
    textTransform: "uppercase",
    letterSpacing: 0.5,
  },
  input: {
    height: 44,
    borderColor: "#CCC",
    borderWidth: 1,
    borderRadius: 8,
    paddingHorizontal: 12,
    backgroundColor: "#FFF",
    marginBottom: 8,
    fontSize: 15,
  },
  sectionHeader: {
    marginTop: 20,
    marginBottom: 10,
    flexDirection: "row",
    alignItems: "center",
    gap: 8,
  },
  sectionHeaderText: {
    fontSize: 11,
    fontWeight: "700",
    color: "#888",
    textTransform: "uppercase",
    letterSpacing: 1,
  },
  sectionDivider: {
    flex: 1,
    height: 1,
    backgroundColor: "#DDD",
  },
  row: {
    flexDirection: "row",
    flexWrap: "wrap",
    gap: 8,
  },
  btn: {
    paddingVertical: 9,
    paddingHorizontal: 14,
    backgroundColor: "#007AFF",
    borderRadius: 8,
  },
  btnDanger: {
    backgroundColor: "#FF3B30",
  },
  btnText: {
    color: "#FFF",
    fontSize: 14,
    fontWeight: "600",
  },
  logBox: {
    backgroundColor: "#1C1C1E",
    borderRadius: 10,
    padding: 12,
    minHeight: 160,
    maxHeight: 320,
  },
  logText: {
    color: "#E5E5EA",
    fontSize: 13,
    fontFamily: "monospace",
    lineHeight: 20,
  },
});
