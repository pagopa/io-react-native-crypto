import * as React from 'react';

import { SafeAreaView, StyleSheet, View, Text, TextInput, Button } from 'react-native';
import { deletePublicKey, generate, getPublicKey, multiply, sign } from '@pagopa/io-react-native-crypto';

export default function App() {
  const [result, setResult] = React.useState<number | undefined>();
  const [logText, setLogText] = React.useState<string | undefined>();
  const [keyTag, setKeyTag] = React.useState<string>("key");

  React.useEffect(() => {
    multiply(3, 7).then(setResult);
  }, []);

  return (
    <SafeAreaView style={{ flex: 1, padding: 20, backgroundColor: "#ccc" }}>
      <View style={{
        flex: 1
      }}>
        <Text style={{ fontWeight: "bold", height: "auto" }}>Ket tag: </Text>
        <TextInput
          onChangeText={newTag => setKeyTag(newTag)}
          defaultValue={keyTag}
          style={{
            marginVertical: 8,
            height: 40,
            borderColor: "black",
            borderWidth: 1,
            borderRadius: 10
          }}
          placeholder="key tag"
        />
        <View style={{
          flexDirection: "row",
          justifyContent: "space-between"
        }}>
          <Button
            title="sign"
            color="#FF0F0C"
            onPress={() => {
              sign("", keyTag)
                .then((value) => {
                  console.log(JSON.stringify(value));
                  setLogText(JSON.stringify(value));
                })
                .catch((reason) => {
                  console.log(reason);
                  setLogText(JSON.stringify(reason));
                })
            }} />
          <Button
            title="get"
            color="#FF0000"
            onPress={() => {
              getPublicKey(keyTag)
                .then((value) => {
                  console.log(JSON.stringify(value));
                  setLogText(JSON.stringify(value));
                })
                .catch((reason) => {
                  console.log(reason);
                  setLogText(JSON.stringify(reason));
                })
            }} />
          <Button
            title="create"
            color="#FF0CCF"
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
                })
            }} />
          <Button
            title="delete"
            color="#0000FF"
            onPress={() => {
              deletePublicKey(keyTag)
                .then((value) => {
                  console.log(`${JSON.stringify(value)}`);
                  setLogText(JSON.stringify((value)));
                })
                .catch((reason) => {
                  console.log(reason);
                  setLogText(JSON.stringify(reason));
                })
            }} />
        </View>
        <Text style={{
          marginVertical: 16,
          flexGrow: 1,
          padding: 8,
          backgroundColor: "#CCDDCC"
        }}>{logText}</Text>
      </View>
      <Text style={{ backgroundColor: "#fff" }}>Result: {result}</Text>
    </SafeAreaView>
  );
}