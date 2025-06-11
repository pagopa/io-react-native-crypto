import * as React from 'react';

import {
  SafeAreaView,
  View,
  Text,
  TextInput,
  Button,
  ScrollView,
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
  mockCertificateChainReal,
} from './mocks/certifaces.mock';

export default function App() {
  const [logText, setLogText] = React.useState<string | undefined>();
  const [keyTag, setKeyTag] = React.useState<string>('key');

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
            justifyContent: 'space-between',
          }}
        >
          <ScrollView horizontal>
            <Button
              title="sign"
              onPress={() => {
                sign("Ceci n'est pas une nonce", keyTag)
                  .then((value) => {
                    console.log(JSON.stringify(value));
                    setLogText(JSON.stringify(value));
                  })
                  .catch((reason: CryptoError) => {
                    console.log(reason);
                    setLogText(`${reason}`);
                  });
              }}
            />
            <Button
              title="get"
              onPress={() => {
                getPublicKey(keyTag)
                  .then((value) => {
                    console.log(JSON.stringify(value));
                    setLogText(JSON.stringify(value));
                  })
                  .catch((reason: CryptoError) => {
                    console.log(reason);
                    setLogText(`${reason}`);
                  });
              }}
            />
            <Button
              title="getFixed"
              onPress={() => {
                getPublicKeyFixed(keyTag)
                  .then((value) => {
                    console.log(JSON.stringify(value));
                    setLogText(JSON.stringify(value));
                  })
                  .catch((reason: CryptoError) => {
                    console.log(reason);
                    setLogText(`${reason}`);
                  });
              }}
            />
            <Button
              title="create"
              onPress={() => {
                generate(keyTag)
                  .then((value) => {
                    console.log(JSON.stringify(value));
                    setLogText(JSON.stringify(value));
                  })
                  .catch((reason: CryptoError) => {
                    console.log(reason);
                    setLogText(`${reason}`);
                  });
              }}
            />
            <Button
              title="delete"
              onPress={() => {
                deleteKey(keyTag)
                  .then(() => {
                    console.log('true');
                    setLogText('true');
                  })
                  .catch((reason: CryptoError) => {
                    console.log(reason);
                    setLogText(`${reason}`);
                  });
              }}
            />
            <Button
              title="isKeyStrongboxBacked"
              onPress={() => {
                isKeyStrongboxBacked(keyTag)
                  .then((result) => {
                    console.log(result);
                    setLogText(result ? 'true' : 'false');
                  })
                  .catch((reason: CryptoError) => {
                    console.log(reason);
                    setLogText(`${reason}`);
                  });
              }}
            />
            <Button
              title="verifyCertificates"
              onPress={() => {
                verifyCertificateChain(mockCertificateChainReal.x5c, mockCertificateChainReal.trustAnchorCert, {
                  connectTimeout: 10000,
                  readTimeout: 10000,
                  requireCrl: true
                })
                  .then((result) => {
                    console.log(result);
                    setLogText(JSON.stringify(result));
                  })
                  .catch((reason: CryptoError) => {
                    console.log(reason);
                    setLogText(`${reason}`);
                  })
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
