import {
    ABIDecoder,
    ABIEncoder,
    Bytes,
    Checksum256,
    KeyType,
    PublicKey,
    Signature,
} from '@wharfkit/antelope'
import {decode as cborDecode} from 'cborg'
import elliptic from 'elliptic'

import {Decoder} from './decoder'

const {ec} = elliptic

export function createPublic(
    attestationResponse: {
        attestationObject: ArrayBuffer
        clientDataJSON: ArrayBuffer
    },
    logging = false
) {
    const clientData = decodeBinaryJson(attestationResponse.clientDataJSON)
    const origin = clientData.origin
    if (typeof origin !== 'string') {
        throw new Error('Missing origin in client data')
    }
    const originUrl = new URL(origin)
    if (originUrl.protocol !== 'https:') {
        throw new Error('WebAuthn keys require https')
    }

    const attestationObject = cborDecode(new Uint8Array(attestationResponse.attestationObject))
    if (!(attestationObject.authData instanceof Uint8Array)) {
        throw new Error('Missing auth data')
    }

    const authData = decodeAuthData(attestationObject.authData)
    const ecPoint = getECPoint(authData.credentialPublicKey)

    const compressed = new Uint8Array(33)
    compressed[0] = ecPoint.y[31] & 0x01 ? 0x03 : 0x02
    compressed.set(ecPoint.x, 1)

    const abiEncoder = new ABIEncoder()
    abiEncoder.writeArray(compressed)
    abiEncoder.writeByte(getUserDataFlag(authData.flags, logging))
    abiEncoder.writeString(originUrl.hostname)

    return new PublicKey(KeyType.WA, abiEncoder.getBytes())
}

export function createSignature(
    publicKey: PublicKey,
    assertionResponse: {
        signature: ArrayBuffer
        authenticatorData: ArrayBuffer
        clientDataJSON: ArrayBuffer
    }
) {
    const decoder = new Decoder(assertionResponse.signature).derDecoder(0x30)
    const r = fixPoint(decoder.readDer(0x02))
    const s = fixPoint(decoder.readDer(0x02))

    const authenticatorData = Bytes.from(assertionResponse.authenticatorData)
    const clientDataJSON = Bytes.from(assertionResponse.clientDataJSON)

    const message = new Bytes()
    message.append(authenticatorData)
    message.append(Checksum256.hash(clientDataJSON))

    const curve = new ec('p256')
    const pk = curve.keyFromPublic(publicKey.data.array.slice(0, 33)).getPublic()
    const m = Checksum256.hash(message).array
    const recid = (curve.getKeyRecoveryParam as any)(m, {r, s}, pk)

    const encoder = new ABIEncoder()
    encoder.writeByte(recid + 31)
    encoder.writeArray(r)
    encoder.writeArray(s)
    authenticatorData.toABI(encoder)
    clientDataJSON.toABI(encoder)

    return new Signature(KeyType.WA, encoder.getBytes())
}

export function recoverPublic(signature: Signature, message: Bytes, logging = false): PublicKey {
    const signatureData = signature.data.array
    const messageDigest = Checksum256.hash(message).array

    const recid = signatureData[0] - 31
    const r = signatureData.subarray(1, 33)
    const s = signatureData.subarray(33, 33 + 32)
    const curve = new ec('p256')
    const point = curve.recoverPubKey(messageDigest, {r, s}, recid)
    const compressedKeyPoint = new Uint8Array(point.encodeCompressed())

    const extraDataView = signatureData.subarray(65)
    const extraDataDecoder = new ABIDecoder(extraDataView)

    const authenticatorDataBytes = Bytes.fromABI(extraDataDecoder)
    const clientDataJSONBytes = Bytes.fromABI(extraDataDecoder)

    const clientData = decodeBinaryJson(clientDataJSONBytes.array.slice().buffer)
    const origin = clientData.origin
    if (typeof origin !== 'string') {
        throw new Error('Missing origin in client data during recovery')
    }
    const originUrl = new URL(origin)
    if (originUrl.protocol !== 'https:') {
        throw new Error('WebAuthn keys require https')
    }

    const authDataForFlagsDecoder = new Decoder(authenticatorDataBytes.array)
    if (!authDataForFlagsDecoder.canRead(32 + 1)) {
        throw new Error('Authenticator data is too short to read flags.')
    }
    authDataForFlagsDecoder.readArray(32)

    const abiEncoder = new ABIEncoder()
    abiEncoder.writeArray(compressedKeyPoint)

    const flags = authDataForFlagsDecoder.readByte()
    abiEncoder.writeByte(getUserDataFlag(flags, logging))

    abiEncoder.writeString(originUrl.hostname)

    return new PublicKey(KeyType.WA, abiEncoder.getBytes())
}

export function getUserDataFlag(flags: number, logging = false): number {
    let byte = 0x00
    if (flags & 0x01 /* user present */) {
        if (logging) {
            // eslint-disable-next-line no-console
            console.info('present flag', flags)
        }
        byte = 0x01
    }
    if (flags & 0x04 /* user verified */) {
        if (logging) {
            // eslint-disable-next-line no-console
            console.info('verified flag', flags)
        }
        byte = 0x02
    }
    if (logging) {
        // eslint-disable-next-line no-console
        console.info('final user data flag:', byte)
    }
    return byte
}

export function verifyPublic(signature: Signature, message: Bytes, publicKey: PublicKey) {
    const signatureData = signature.data.array
    const messageDigest = Checksum256.hash(message).array
    const publicKeyData = publicKey.getCompressedKeyBytes()

    const curve = new ec('p256')
    const r = signatureData.subarray(1, 33)
    const s = signatureData.subarray(33, 33 + 32)
    return curve.verify(messageDigest, {r, s}, publicKeyData as any)
}

export function recoverPotentialPublicKeysFromAssertion(
    assertionResponse: AuthenticatorAssertionResponse,
    logging = false
): PublicKey[] {
    const authenticatorData = Bytes.from(assertionResponse.authenticatorData)
    const clientDataJSON = Bytes.from(assertionResponse.clientDataJSON)

    const message = new Bytes()
    message.append(authenticatorData)
    message.append(Checksum256.hash(clientDataJSON))

    const decoder = new Decoder(assertionResponse.signature).derDecoder(0x30)
    const r = fixPoint(decoder.readDer(0x02))
    const s = fixPoint(decoder.readDer(0x02))
    const keys: PublicKey[] = []
    for (let recid = 0; recid < 4; recid++) {
        try {
            const encoder = new ABIEncoder()
            encoder.writeByte(recid + 31)
            encoder.writeArray(r)
            encoder.writeArray(s)
            authenticatorData.toABI(encoder)
            clientDataJSON.toABI(encoder)

            const signature = new Signature(KeyType.WA, encoder.getBytes())
            const key = recoverPublic(signature, message, logging)
            keys.push(key)
        } catch (e) {
            // Ignore errors, try next recid
        }
    }
    if (!keys.length) {
        throw new Error('Unable to recover any potential public keys from signature')
    }
    return keys
}

function decodeAuthData(authData: Uint8Array) {
    const decoder = new Decoder(authData)

    const rpIdHash = decoder.readArray(32)
    const flags = decoder.readByte()
    const counter = decoder.readNum(4)
    const aaguid = decoder.readArray(16)
    const credentialId = decoder.readArray(decoder.readNum(2))
    const credentialPublicKey = decodeFirstCborItem(decoder.remainder()) as Map<number, any>

    return {
        rpIdHash,
        flags,
        counter,
        aaguid,
        credentialId,
        credentialPublicKey,
    }
}

function decodeFirstCborItem(data: Uint8Array): unknown {
    const length = getCborItemLength(data, 0)
    return cborDecode(data.subarray(0, length), {useMaps: true})
}

function getCborItemLength(data: Uint8Array, start: number): number {
    if (start >= data.length) {
        throw new Error('Unexpected end of CBOR data')
    }

    const first = data[start]
    const majorType = first >> 5
    const additional = first & 0x1f

    const {value, bytesRead, indefinite} = readCborLength(data, start, additional)
    let pos = start + 1 + bytesRead

    if (majorType === 0 || majorType === 1) {
        return pos - start
    }

    if (majorType === 2 || majorType === 3) {
        if (!indefinite) {
            return pos + value - start
        }

        while (pos < data.length) {
            if (data[pos] === 0xff) {
                return pos + 1 - start
            }
            pos += getCborItemLength(data, pos)
        }

        throw new Error('Unterminated indefinite CBOR string')
    }

    if (majorType === 4 || majorType === 5) {
        const itemCount = indefinite ? -1 : majorType === 5 ? value * 2 : value
        if (!indefinite) {
            for (let i = 0; i < itemCount; i++) {
                pos += getCborItemLength(data, pos)
            }
            return pos - start
        }

        while (pos < data.length) {
            if (data[pos] === 0xff) {
                return pos + 1 - start
            }
            pos += getCborItemLength(data, pos)
        }

        throw new Error('Unterminated indefinite CBOR container')
    }

    if (majorType === 6) {
        return pos + getCborItemLength(data, pos) - start
    }

    if (majorType === 7) {
        if (additional < 24 || additional === 31) {
            return pos - start
        }
        if (additional === 24) {
            return pos + 1 - start
        }
        if (additional === 25) {
            return pos + 2 - start
        }
        if (additional === 26) {
            return pos + 4 - start
        }
        if (additional === 27) {
            return pos + 8 - start
        }
    }

    throw new Error(`Unsupported CBOR major type: ${majorType}`)
}

function readCborLength(
    data: Uint8Array,
    start: number,
    additional: number
): {value: number; bytesRead: number; indefinite: boolean} {
    if (additional < 24) {
        return {value: additional, bytesRead: 0, indefinite: false}
    }

    if (additional === 24) {
        ensureCborBytes(data, start + 1, 1)
        return {value: data[start + 1], bytesRead: 1, indefinite: false}
    }

    if (additional === 25) {
        ensureCborBytes(data, start + 1, 2)
        const view = new DataView(data.buffer, data.byteOffset + start + 1, 2)
        return {value: view.getUint16(0), bytesRead: 2, indefinite: false}
    }

    if (additional === 26) {
        ensureCborBytes(data, start + 1, 4)
        const view = new DataView(data.buffer, data.byteOffset + start + 1, 4)
        return {value: view.getUint32(0), bytesRead: 4, indefinite: false}
    }

    if (additional === 27) {
        ensureCborBytes(data, start + 1, 8)
        const view = new DataView(data.buffer, data.byteOffset + start + 1, 8)
        const value = Number(view.getBigUint64(0))
        if (!Number.isSafeInteger(value)) {
            throw new Error('CBOR length exceeds safe integer range')
        }
        return {value, bytesRead: 8, indefinite: false}
    }

    if (additional === 31) {
        return {value: 0, bytesRead: 0, indefinite: true}
    }

    throw new Error(`Invalid CBOR additional information: ${additional}`)
}

function ensureCborBytes(data: Uint8Array, start: number, length: number): void {
    if (start + length > data.length) {
        throw new Error('Unexpected end of CBOR data')
    }
}

function getECPoint(credentialPublicKey: Map<number, any>) {
    const kty = credentialPublicKey.get(1)
    if (kty !== 2 /* EC */) {
        throw new Error(`Unsupported key type: ${kty}`)
    }
    const alg = credentialPublicKey.get(3)
    if (alg !== -7 /* EC2 */) {
        throw new Error(`Unsupported key algorithm: ${alg}`)
    }
    const crv = credentialPublicKey.get(-1)
    if (crv !== 1 /*P-256*/) {
        throw new Error(`Unsupported ec key curve: ${crv}`)
    }
    const x = credentialPublicKey.get(-2)
    const y = credentialPublicKey.get(-3)
    if (!(x instanceof Uint8Array) || !(y instanceof Uint8Array)) {
        throw new Error('Invalid public key data')
    }
    return {x, y}
}

function decodeBinaryJson(data: ArrayBuffer) {
    const decoder = new TextDecoder()
    return JSON.parse(decoder.decode(data))
}

// chrome sometimes returns curve points that are not 32 bytes, so we need to make sure they are
function fixPoint(x: Uint8Array) {
    if (x.length === 32) {
        return x
    }
    const rv = new Uint8Array(32)
    rv.fill(0)
    let si = 0
    while (x[si] === 0 && si < x.length - 1) {
        si++
    }
    rv.set(x.slice(si), 32 - x.length + si)
    return rv
}
