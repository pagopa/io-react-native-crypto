import * as React from 'react';

import { SafeAreaView, StyleSheet, View, Text, TextInput, Button } from 'react-native';
import { generate, getPublicKey, multiply } from '@pagopa/io-react-native-crypto';

export default function App() {
  const [result, setResult] = React.useState<number | undefined>();

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
            title="get"
            color="#FF0000"
            onPress={() => {
    getPublicKey("ec").then((value) => {
      console.log(`${JSON.stringify(value)}`);
    })
      .catch((reason) => {
        console.log(reason);
      })
    getPublicKey("rsa").then((value) => {
      console.log(`${JSON.stringify(value)}`);
    })
      .catch((reason) => {
        console.log(reason);
      })
            }} />
          <Button
            title="create"
            color="#FF0CCF"
            onPress={() => {

    generate("ec").then((value) => {
      console.log(`${JSON.stringify(value)}`);
    })
      .catch((reason) => {
        console.log(reason);
      })
    generate("rsa").then((value) => {
      console.log(`${JSON.stringify(value)}`);
    })
      .catch((reason) => {
        console.log(reason);
      })
            }} />
          <Button
            title="delete"
            color="#0000FF"
            onPress={() => {

            }} />
        </View>
        <Text style={{
          marginVertical: 16,
          flexGrow: 1,
          padding: 8,
          backgroundColor: "#CCDDCC"
        }}></Text>
      </View>
      <Text style={{backgroundColor:"#fff"}}>Result: {result}</Text>
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1
  },
  box: {
    width: 60,
    height: 60,
    marginVertical: 20,
  },
});
