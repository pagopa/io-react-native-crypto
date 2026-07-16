import * as React from 'react';

import {
  SafeAreaView,
  View,
  Text,
  TextInput,
  Button,
  ScrollView,
  Switch,
} from 'react-native';
import {
  CryptoError,
  deleteKey,
  generate,
  getPublicKey, getPublicKeyFixed,
  isKeyStrongboxBacked,
  sign, verifyCertificateChain,
} from '@pagopa/io-react-native-crypto';
import {
  mockCertificateChainReal, mockCertNoCrl,
} from './mocks/certifaces.mock';

export default function App() {
  const [logText, setLogText] = React.useState<string | undefined>();
  const [keyTag, setKeyTag] = React.useState<string>('key');
  const [requireAuthentication, setRequireAuthentication] =
    React.useState<boolean>(false);

  const logPromiseResult = (method: string, promise: Promise<unknown>) => {
    promise
      .then((value) => {
        const text = `${method}: ${value === undefined ? 'true' : JSON.stringify(value)}`;
        console.log(text);
        setLogText(text);
      })
      .catch((reason: CryptoError) => {
        console.log(method, reason);
        setLogText(`${method}: ${reason}`);
      });
  };

  return (
    <SafeAreaView style={{ flex: 1, padding: 20 }}>
      <View
        style={{
          flex: 1,
          padding: 16,
        }}
      >
        <Text style={{ fontWeight: 'bold', height: 'auto' }}>Ket tag: </Text>
        <TextInput
          onChangeText={(newTag) => setKeyTag(newTag)}
          defaultValue={keyTag}
          style={{
            marginVertical: 8,
            height: 40,
            borderColor: 'black',
            borderWidth: 1,
            borderRadius: 10,
          }}
          placeholder="key tag"
        />
        <View
          style={{
            flexDirection: 'row',
            alignItems: 'center',
            justifyContent: 'space-between',
            marginBottom: 8,
          }}
        >
          <Text>Require authentication (biometric / PIN) on create</Text>
          <Switch
            value={requireAuthentication}
            onValueChange={setRequireAuthentication}
          />
        </View>
        <View
          style={{
            flexDirection: 'row',
            justifyContent: 'space-between',
          }}
        >
          <ScrollView horizontal>
            <Button
              title="sign"
              onPress={() => {
                logPromiseResult(
                  'sign',
                  sign("Ceci n'est pas une nonce", keyTag)
                );
              }}
            />
            <Button
              title="get"
              onPress={() => {
                logPromiseResult('getPublicKey', getPublicKey(keyTag));
              }}
            />
            <Button
              title="getFixed"
              onPress={() => {
                logPromiseResult('getPublicKeyFixed', getPublicKeyFixed(keyTag));
              }}
            />
            <Button
              title="create"
              onPress={() => {
                logPromiseResult(
                  'generate',
                  generate(
                    keyTag,
                    requireAuthentication
                      ? {
                          requireAuthentication: true,
                          authenticationPrompt: {
                            title: 'Confirm signing',
                            subtitle: `Authenticate to use the key "${keyTag}"`,
                            cancel: 'Cancel',
                          },
                        }
                      : undefined
                  )
                );
              }}
            />
            <Button
              title="delete"
              onPress={() => {
                logPromiseResult('delete', deleteKey(keyTag));
              }}
            />
            <Button
              title="isKeyStrongboxBacked"
              onPress={() => {
                logPromiseResult(
                  'isKeyStrongboxBacked',
                  isKeyStrongboxBacked(keyTag)
                );
              }}
            />
            <Button
              title="verifyCertificatesWithCRL"
              onPress={() => {
                logPromiseResult(
                  'verifyCertificatesWithCRL',
                  verifyCertificateChain(mockCertificateChainReal.x5c, mockCertificateChainReal.trustAnchorCert, {
                    connectTimeout: 10000,
                    readTimeout: 10000,
                    requireCrl: true
                  })
                )
              }}
            />
            <Button
              title="verifyCertificatesNoCRL"
              onPress={() => {
                logPromiseResult(
                  'verifyCertificatesNoCRL',
                  verifyCertificateChain(mockCertNoCrl.x5c, mockCertNoCrl.trustAnchorCert, {
                    connectTimeout: 10000,
                    readTimeout: 10000,
                    requireCrl: false
                  })
                )
              }}
            />
          </ScrollView>
        </View>
        <ScrollView
          style={{
            flexGrow: 1,
            padding: 8,
            marginTop: 16,
            borderRadius: 10,
            backgroundColor: 'gray',
          }}
        >
          <Text
            style={{
              marginVertical: 4,
              color: '#FFF',
            }}
          >
            {logText}
          </Text>
        </ScrollView>
      </View>
    </SafeAreaView>
  );
}
