> [!IMPORTANT]
> This package lives in the WharfKit monorepo at [wharfkit/js/packages/webauthn](https://github.com/wharfkit/js/tree/dev/packages/webauthn), and this repository is archived. Open new issues and pull requests on [wharfkit/js](https://github.com/wharfkit/js).

# eosio-webauthn

Helpers for creating WebAuthn PublicKeys and Signatures using [@wharfkit/antelope](https://github.com/wharfkit/antelope).

## Installation

The `@greymass/webauthn` package is distributed as a module on [npm](https://www.npmjs.com/package/@greymass/webauthn).

```
yarn add @greymass/webauthn
# or
npm install --save @greymass/webauthn
```

## Usage

```ts
import {createPublic, createSignature} from '@greymass/webauthn'

// create credentials
const credentials = await navigator.credentials.create({
    publicKey: {
        // Your website domain name and display name
        // note that your website must be served over https or signatures will not be valid
        rp: {id: 'greymass.com', name: 'Greymass Inc.'},
        user: {
            // any old bytes(?)
            id: new Uint8Array([0xbe, 0xef, 0xfa, 0xce]),
            // username, usually the users account name but doesn't have to be
            name: 'teamgreymass',
            // will be displayed when the user asks to sing
            displayName: 'Team Greymass @ Jungle 3 TestNet',
        },
        // don't change this, antelope will only work with -7 == EC2
        pubKeyCredParams: [{
            type: 'public-key',
            alg: -7,
        }],
        timeout: 60000,
        // can be any bytes, more than 16 or some browser may complain
        challenge: new Uint8Array([
            0xbe, 0xef, 0xfa, 0xce, 0x22, 0xbe, 0xef, 0xfa, 0xce, 0xbe, 0xef, 0xfa, 0xce,
            0xbe, 0xef, 0xfa, 0xce, 0x22, 0xbe, 0xef, 0xfa, 0xce, 0xbe, 0xef, 0xfa, 0xce,
        ]).buffer,
    },
});
const publicKey = createPublic(credentials.response)
// make sure to persist credentials.id somewhere or you will not be able to sign again with this key!

// ... create or update an existing antelope account to use the new key as a key auth ...

// ... create a transaction using @wharfkit/antelope...

const transactionDigest = transaction.signingDigest(myChainId)

// sign transaction
const assertion = await navigator.credentials.get({
    publicKey: {
        timeout: 60000,
        // credentials we created before
        allowCredentials: [
            {
                id: credentials.rawId,
                type: 'public-key',
            },
        ],
        // the transaction you want to sign
        challenge: transactionDigest.array.buffer,
    },
})

const signature = createSignature(publicKey, assertion.response)
const signedTransaction = SignedTransaction.from({...transaction, signatures: [signature])

/// ... broadcast your signed transaction to the network ....

```

## Developing

You need [Make](https://www.gnu.org/software/make/), [node.js](https://nodejs.org/en/) and [yarn](https://classic.yarnpkg.com/en/docs/install) installed.

Clone the repository and run `make` to checkout all dependencies and build the project. See the [Makefile](./Makefile) for other useful targets. Before submitting a pull request make sure to run `make format`.

---

Made with ☕️ & ❤️ by [Greymass](https://greymass.com), if you find this useful please consider [supporting us](https://greymass.com/support-us).
