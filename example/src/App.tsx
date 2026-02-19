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
  generate,
  digest,
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

// ─── Helpers ─────────────────────────────────────────────────────────────────

const toHex = (bytes: Uint8Array) =>
  Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");

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

        {/* ── Section 3: Hash ── */}
        <SectionHeader title="Hash" />
        <View style={styles.row}>
          <Btn
            title="digest (string)"
            onPress={() =>
              digest("Hello, world!", "sha-256")
                .then((bytes) =>
                  log(`digest("Hello, world!")\n${toHex(bytes)}`)
                )
                .catch(logError)
            }
          />
          <Btn
            title="digest (ArrayBuffer)"
            onPress={async () => {
              const str = "Hello, world!";
              const buf = new Uint8Array(str.length);
              for (let i = 0; i < str.length; i++) buf[i] = str.charCodeAt(i);
              try {
                const bytes = await digest(buf.buffer, "sha-256");
                return log(
                  `digest(ArrayBuffer("Hello, world!"))\n${toHex(bytes)}`
                );
              } catch (reason) {
                return logError(reason);
              }
            }}
          />
          <Btn
            title="Both match?"
            onPress={async () => {
              try {
                const str = "Hello, world!";
                const buf = new Uint8Array(str.length);
                for (let i = 0; i < str.length; i++) buf[i] = str.charCodeAt(i);
                const [a, b] = await Promise.all([
                  digest(str, "sha-256"),
                  digest(buf, "sha-256"),
                ]);
                const match = toHex(a) === toHex(b);
                log(
                  `string and ArrayBuffer produce the same hash: ${match ? "✓ YES" : "✗ NO"}\n\n${toHex(a)}`
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
