import * as React from 'react';
import ProgressBar from 'react-native-progress/Bar';

import { SafeAreaView, View, Text, TextInput, Button, ScrollView } from 'react-native';
import {
  deletePublicKey,
  generate,
  getPublicKey,
  sign,
} from '@pagopa/io-react-native-crypto';

export default function App() {
  const [logText, setLogText] = React.useState<string | undefined>();
  const [keyTag, setKeyTag] = React.useState<string>('key');

  return (
    <SafeAreaView style={{ flex: 1, padding: 20 }}>
      <View
        style={{
          flex: 1,
          padding: 16
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
          <Button
            title="sign"
            onPress={() => {
              sign("Ceci n'est pas une nonce", keyTag)
                .then((value) => {
                  console.log(JSON.stringify(value));
                  setLogText(JSON.stringify(value));
                })
                .catch((reason) => {
                  console.log(reason);
                  setLogText(JSON.stringify(reason));
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
                .catch((reason) => {
                  console.log(reason);
                  setLogText(JSON.stringify(reason));
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
                .catch((reason) => {
                  /*
                    {
                      "nativeStackAndroid":[],
                      "userInfo":{},"AQAB",
                      "message":"Error not specified.",
                      "code":"UNSUPPORTED_DEVICE"
                    } 
                   */
                  console.log(reason);
                  setLogText(JSON.stringify(reason));
                });
            }}
          />
          <Button
            title="delete"
            onPress={() => {
              deletePublicKey(keyTag)
                .then((value) => {
                  console.log(`${JSON.stringify(value)}`);
                  setLogText(JSON.stringify(value));
                })
                .catch((reason) => {
                  console.log(reason);
                  setLogText(JSON.stringify(reason));
                });
            }}
          />
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
              color: '#FFF'
            }}
          >
            {logText}
          </Text>
        </ScrollView>
        <ProgressBar style={{ marginTop: 16 }} indeterminate={true} />
      </View>
    </SafeAreaView>
  );
}
