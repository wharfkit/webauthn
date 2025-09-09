import {assert} from 'chai'
import {Bytes, Checksum256, KeyType, PublicKey} from '@wharfkit/antelope'

import * as lib from '$lib'

suite('index', function () {
    this.timeout(5000)
    this.slow(1000)

    test('createPublic', function () {
        const response = {
            attestationObject: Bytes.from(
                'a363666d74646e6f6e656761747453746d74a068617574684461746158980511e9517abcfeaa5db71dddb8ba831' +
                    'd0513ecdb1bd5f5907421ffa5c909ea3045000000000000000000000000000000000000000000149e093bb39d81' +
                    'de544b40af3fd3894c9a6d5214eba5010203262001215820d9eee421c986d509f9e575c08f4a3ab45bca6896a69' +
                    'fb4e83379a8bc9fb6af982258202ddb029af756c10243446b888892d91f82e63c101d5715308cb0155900ec862f'
            ).array.buffer,
            clientDataJSON: Bytes.from(
                '7b2274797065223a22776562617574686e2e637265617465222c2263' +
                    '68616c6c656e6765223a2276755f367a694b2d375f724f76755f367a' +
                    '7237762d73346976755f367a7237762d7334222c226f726967696e22' +
                    '3a2268747470733a2f2f79656c6c6f776167656e74732e636f6d227d'
            ).array.buffer,
        }

        const key = lib.createPublic(response)
        assert.equal(
            key,
            'PUB_WA_2NVXH8vKM57G6raNdktPvTuMxBM9EeuK8uquDGhaXPfMV7AcE5UWz1o7ZrPiDQGwNBF4oob3pVy'
        )
    })

    test('createSignature', function () {
        const response = {
            authenticatorData: Bytes.from(
                '0511e9517abcfeaa5db71dddb8ba831d0513ecdb1bd5f5907421ffa5c909ea300500000000'
            ).array.buffer,
            signature: Bytes.from(
                '3044022047ef146e8708bdcc0b7a92fc01685b0b37f522c313972b71fe988d7b0c69cd' +
                    '7d02206453d15bb8f566a3d2285877a7e681c6b8b5c610290e45026bbe091e99aadb9a'
            ).array.buffer,
            clientDataJSON: Bytes.from(
                '7b2274797065223a22776562617574686e2e676574222c226368616c6c656e6765223a22516b4a43516b4a43516b4a43516b4a43516b4a43516b4a43516b4a43516b4a43516b4a43516b4a43516b49222c226f726967696e223a2268747470733a2f2f79656c6c6f776167656e74732e636f6d227d'
            ).array.buffer,
        }
        const sig = lib.createSignature(
            PublicKey.from(
                'PUB_WA_2NVXH8vKM57G6raNdktPvTuMxBM9EeuK8uquDGhaXPfMV7SMFd4dUgza7xGStLnVJs5Xdhhm5fs'
            ),
            response
        )
        assert.equal(
            sig,
            'SIG_WA_PAmH7fjMVadx19QK8jQooKFsL8szj81CFMPAfAuZ9GkSPQczccCEVCuMKAFS9YP7CvkmzXYULYxvdBMx3Chi9Ld2tPkvtbC6TEYY3QS7fDmZLBQjPCatUncLQneG97KMPCohZzuUyTzr1ojbufyBJ65BNRrYSVQynzcJoVXuym8DLhm5HZf23UdKmb79rGCYkwP4xWeEgowarGmnnxvMsjfRxTrQHeh67TMKiVkz8r8unHh7Zkf5jTPVsKXjSTjEYuwj4aBWpSEXkVvYcWZ3wbSKs9gHjKjY8m22Qeye45D1NQe7vKR'
        )
    })

    test('createSignature (chrome)', function () {
        const response = {
            authenticatorData: Bytes.from(
                'ff7acd7d1bf23a2faae6ac29a0ad894cf65587fb8d20959496c0800788e0f83f0100000011'
            ).array.buffer,
            signature: Bytes.from(
                '30450220466669c1e5fe77663a886f10d373c624d067f3f74f03842b81b8506b3e703af7022100ea0069e93571392507a8e5fb682929afde03482cb034b3b2141dd90eb23298e1'
            ).array.buffer,
            clientDataJSON: Bytes.from(
                '7b2274797065223a22776562617574686e2e676574222c226368616c6c656e6765223a22776b3067644b7464316b693834385a314965736472556951366a7a6c755658595438653557494b73597951222c226f726967696e223a2268747470733a2f2f313038612d382d33372d34332d3139352e6e67726f6b2e696f222c2263726f73734f726967696e223a66616c73652c226f746865725f6b6579735f63616e5f62655f61646465645f68657265223a22646f206e6f7420636f6d7061726520636c69656e74446174614a534f4e20616761696e737420612074656d706c6174652e205365652068747470733a2f2f676f6f2e676c2e716a7a397a6b2f796162506578227d'
            ).array.buffer,
        }
        const sig = lib.createSignature(
            PublicKey.from(
                'PUB_WA_4b5bGn5QobA585zgvjXbcXDbufsTpRVipnuaYwszHdKRLS2g74KFbkjDfL4wg2ZR8eGYUd66zXjzT7vEFV7apGp'
            ),
            response
        )
        assert.equal(
            sig.toString(),
            'SIG_WA_2qJAY76sbx2NhQ8obMsemfruwTNXcy16dy1W9tt9iKyWi3UgfNTmkYAdmz6V552PD8K3pJ35w6VSfnAmhCim6CqQCTs4rJsJnVRnGcXJ2HvacRpd59Qp8yHZwgtC2uDFELyAAj2f2jnPQoEmC8NWaDdDzvBc59pzELuBLrv4Yant5szZBhK3fcpRJzohcFusKfiQQcWSLVtWs4h6FVvBe4zd2UPPqwq4tsEHVP4dcsxu7XLwQeiQyUfBKjBWV1wunwPeoyHMZCd2B3esUjMDvGiwaiP6TA7PvuEFZEw4UtAKKhLbNFYfAZxhxZrcB31w3K8JSK5iwAReLStjyiZVgvrLPDUEuvwdrKVTT5PcVfcTg9G9jPB5pRYjhF4CmdQZ82VZ8KzUpUJsqKshXL1GAKJXZAuQ8QwDgzninoJV5SeTGQyide4euR43RHTCvUyeKcRDSV3VGSfaSyRaZoBb8WkcuXvYAArcBC1CCBmeyZTT5Xo4o1vuEnFbFwY'
        )
    })

    const waTestData1 = {
        publicKeyString:
            'PUB_WA_2NVXH8vKM57G6raNdktPvTuMxBM9EeuK8uquDGhaXPfMV7SMFd4dUgza7xGStLnVJs5Xdhhm5fs',
        attestationResponse: {
            attestationObject: Bytes.from(
                'a363666d74646e6f6e656761747453746d74a068617574684461746158980511e9517abcfeaa5db71dddb8ba831' +
                    'd0513ecdb1bd5f5907421ffa5c909ea3045000000000000000000000000000000000000000000149e093bb39d81' +
                    'de544b40af3fd3894c9a6d5214eba5010203262001215820d9eee421c986d509f9e575c08f4a3ab45bca6896a69' +
                    'fb4e83379a8bc9fb6af982258202ddb029af756c10243446b888892d91f82e63c101d5715308cb0155900ec862f'
            ).array.buffer,
            clientDataJSON: Bytes.from(
                '7b2274797065223a22776562617574686e2e637265617465222c2263' +
                    '68616c6c656e6765223a2276755f367a694b2d375f724f76755f367a' +
                    '7237762d73346976755f367a7237762d7334222c226f726967696e22' +
                    '3a2268747470733a2f2f79656c6c6f776167656e74732e636f6d227d'
            ).array.buffer,
        },
        assertionResponse: {
            authenticatorData: Bytes.from(
                '0511e9517abcfeaa5db71dddb8ba831d0513ecdb1bd5f5907421ffa5c909ea300500000000'
            ).array.buffer,
            signature: Bytes.from(
                '3044022047ef146e8708bdcc0b7a92fc01685b0b37f522c313972b71fe988d7b0c69cd' +
                    '7d02206453d15bb8f566a3d2285877a7e681c6b8b5c610290e45026bbe091e99aadb9a'
            ).array.buffer,
            clientDataJSON: Bytes.from(
                // For simplicity, reusing clientDataJSON from attestation here for this test case
                '7b2274797065223a22776562617574686e2e676574222c226368616c6c656e6765223a22516b4a43516b4a43516b4a43516b4a43516b4a43516b4a43516b4a43516b4a43516b4a43516b4a43516b49222c226f726967696e223a2268747470733a2f2f79656c6c6f776167656e74732e636f6d227d'
            ).array.buffer,
        },
    }

    test('verifyPublic', function () {
        const originalPublicKey = PublicKey.from(waTestData1.publicKeyString)
        const signature = lib.createSignature(originalPublicKey, waTestData1.assertionResponse)

        const authenticatorData = Bytes.from(waTestData1.assertionResponse.authenticatorData)
        const clientDataJSON = Bytes.from(waTestData1.assertionResponse.clientDataJSON)
        const message = new Bytes()
        message.append(authenticatorData)
        message.append(Checksum256.hash(clientDataJSON))

        assert.isTrue(
            lib.verifyPublic(signature, message, originalPublicKey),
            'should succeed with correct data'
        )

        const anotherPublicKey = PublicKey.from(
            'PUB_WA_4b5bGn5QobA585zgvjXbcXDbufsTpRVipnuaYwszHdKRLS2g74KFbkjDfL4wg2ZR8eGYUd66zXjzT7vEFV7apGp'
        )
        assert.isFalse(
            lib.verifyPublic(signature, message, anotherPublicKey),
            'should fail with incorrect public key'
        )

        const wrongMessage = Bytes.from('some other message', 'utf8')
        assert.isFalse(
            lib.verifyPublic(signature, wrongMessage, originalPublicKey),
            'should fail with incorrect message'
        )
    })

    test('recoverPublic', function () {
        const fullOriginalPublicKey = lib.createPublic(waTestData1.attestationResponse)
        const signature = lib.createSignature(fullOriginalPublicKey, waTestData1.assertionResponse)

        const authenticatorData = Bytes.from(waTestData1.assertionResponse.authenticatorData)
        const clientDataJSON = Bytes.from(waTestData1.assertionResponse.clientDataJSON)
        const message = new Bytes()
        message.append(authenticatorData)
        message.append(Checksum256.hash(clientDataJSON))

        const recoveredPublicKey = lib.recoverPublic(signature, message)

        assert.equal(recoveredPublicKey.type, KeyType.WA, 'recovered key type should be WA')

        assert.isTrue(
            recoveredPublicKey.equals(fullOriginalPublicKey),
            'recovered public key should equal the fully constructed original public key'
        )

        assert.isTrue(
            lib.verifyPublic(signature, message, recoveredPublicKey),
            'recovered key should be able to verify its own signature'
        )

        const wrongMessage = Bytes.from('another wrong message', 'utf8')
        assert.isFalse(
            lib.recoverPublic(signature, wrongMessage).equals(fullOriginalPublicKey),
            'recovered key from wrong message should not match'
        )
    })

    test('recoverPublicFromAssertionResponse', function () {
        // The expected public key (this should match the key used to create the signature)
        const expectedKey = PublicKey.from(
            'PUB_WA_6VkTUGW4F3bLboSoGQD5dGwvHJCjkJNboSe74wV3Xg7XeLJQ6VXeRYAqvJXkyRJNA'
        )

        // Construct a mock AuthenticatorAssertionResponse
        const authenticatorData = Buffer.from(
            'SZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2MdAAAAAA==',
            'base64'
        )
        const clientDataJSON = Buffer.from(
            'eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoidldCOEs1Q2dLelBfOFdNWmpTZC1ydyIsIm9yaWdpbiI6Imh0dHBzOi8vbG9jYWxob3N0OjUxNzMiLCJjcm9zc09yaWdpbiI6ZmFsc2V9',
            'base64'
        )
        const signature = Buffer.from(
            'MEUCIFsuMcPcYAdtIk8lj8QA5WfOUyKZJmCeS9CfJ/xwHKZaAiEAmWBxT5LlZhPxn1CpHRURXsfxxoy6tAEfuuoIL+LITtY=',
            'base64'
        )
        const response: AuthenticatorAssertionResponse = {
            authenticatorData: authenticatorData.buffer.slice(
                authenticatorData.byteOffset,
                authenticatorData.byteOffset + authenticatorData.byteLength
            ) as ArrayBuffer,
            clientDataJSON: clientDataJSON.buffer.slice(
                clientDataJSON.byteOffset,
                clientDataJSON.byteOffset + clientDataJSON.byteLength
            ) as ArrayBuffer,
            signature: signature.buffer.slice(
                signature.byteOffset,
                signature.byteOffset + signature.byteLength
            ) as ArrayBuffer,
            userHandle: new ArrayBuffer(0),
        }

        // Recover the public key from the assertion response
        const recoveredPublicKey = lib.recoverPublicFromAssertionResponse(response)

        // Verify the recovered public key
        assert.equal(recoveredPublicKey.type, KeyType.WA, 'recovered key type should be WA')
        assert.isTrue(
            recoveredPublicKey.equals(expectedKey),
            'recovered public key should equal the fully constructed original public key'
        )
    })
})
