import * as React from 'react';

import { StyleSheet, View, Text } from 'react-native';
import { generate, getPublicKey, multiply } from '@pagopa/io-react-native-crypto';

export default function App() {
  const [result, setResult] = React.useState<number | undefined>();

  React.useEffect(() => {
    multiply(3, 7).then(setResult);
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
  }, []);

  return (
    <View style={styles.container}>
      <Text>Result: {result}</Text>
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    alignItems: 'center',
    justifyContent: 'center',
  },
  box: {
    width: 60,
    height: 60,
    marginVertical: 20,
  },
});
