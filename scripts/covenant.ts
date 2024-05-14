// @ts-ignore
import btc = require('bitcore-lib-inquisition');
import axios from 'axios';
import { Tap } from '@cmdcode/tapscript'  // Requires node >= 19
import ecurve = require('ecurve');
import sha256 = require('js-sha256');
import BigInteger = require('bigi')

import dotenv = require('dotenv');
dotenv.config();

const curve = ecurve.getCurveByName('secp256k1');

async function fetchP2WPKHUtxos(address: btc.Address): Promise<any[]> {
    const url = `https://explorer.bc-2.jp/api/address/${address.toString()}/utxo`;

    let res = []
    try {
        // Make a GET request to the URL using axios
        const response = await axios.get(url);

        if (response.data) {
            for (let i = 0; i < response.data.length; i++) {
                const e = response.data[i]
                const utxo = {
                    address: address.toString(),
                    txId: e.txid,
                    outputIndex: e.vout,
                    script: new btc.Script(address),
                    satoshis: e.value
                };
                res.push(utxo)
            }
        }
    } catch (error) { // Handle any errors that occurred during the request
        console.error('Failed to fetch data:', error);
    }
    return res
}

function hashSHA256(buff: Buffer | string) {
    return Buffer.from(sha256.sha256.create().update(buff).array());
}

function getSigHash(
    transaction: btc.Transaction,
    tapleafHash: Buffer,
    inputIndex = 0,
    sigHashType = 0x00
) {
    //const sighash = btc.Transaction.Sighash.sighash(transaction, sigHashType, inputIndex, subscript);
    const execdata = {
        annexPresent: false,
        annexInit: true,
        tapleafHash: tapleafHash,
        tapleafHashInit: true,
        //validationWeightLeft: 110,
        //validationWeightLeftInit: true,
        codeseparatorPos: new btc.crypto.BN(4294967295),
        codeseparatorPosInit: true
    }
    return {
        preimage: btc.Transaction.SighashSchnorr.sighashPreimage(transaction, sigHashType, inputIndex, 3, execdata),
        hash: btc.Transaction.SighashSchnorr.sighash(transaction, sigHashType, inputIndex, 3, execdata)
    }
}


function getE(
    sighash: Buffer
) {
    const Gx = curve.G.affineX.toBuffer(32);

    const tagHash = hashSHA256('BIP0340/challenge')
    const tagHashMsg = Buffer.concat([Gx, Gx, sighash])
    const taggedHash = hashSHA256(Buffer.concat([tagHash, tagHash, tagHashMsg]))

    return BigInteger.fromBuffer(taggedHash).mod(curve.n);
}

function splitSighashPreimage(preimage: Buffer) {
    return {
        tapSighash1: preimage.slice(0, 32),
        tapSighash2: preimage.slice(32, 64),
        epoch: preimage.slice(64, 65),
        sighashType: preimage.slice(65, 66),
        txVersion: preimage.slice(66, 70),
        nLockTime: preimage.slice(70, 74),
        hashPrevouts: preimage.slice(74, 106),
        hashSpentAmounts: preimage.slice(106, 138),
        hashScripts: preimage.slice(138, 170),
        hashSequences: preimage.slice(170, 202),
        hashOutputs: preimage.slice(202, 234),
        spendType: preimage.slice(234, 235),
        inputNumber: preimage.slice(235, 239),
        tapleafHash: preimage.slice(239, 271),
        keyVersion: preimage.slice(271, 272),
        codeseparatorPosition: preimage.slice(272)
    };
}


async function main() {
    const seckey = new btc.PrivateKey(process.env.PRIVATE_KEY, btc.Networks.testnet) 
    const pubkey = seckey.toPublicKey()
    const addrP2WPKH = seckey.toAddress(null, btc.Address.PayToWitnessPublicKeyHash)

    //const Gx = '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'
    const Gx = curve.G.affineX.toBuffer(32);
    const tagHash = hashSHA256('BIP0340/challenge')
    const ePreimagePrefix = Buffer.concat([tagHash, tagHash, Gx, Gx])

    // Make covenant enforce the following output.
    const paymentOut = new btc.Transaction.Output({
        satoshis: 1000,
        script: btc.Script(addrP2WPKH)
    })

    const preimagePrefix = 'f40a48df4b2a70c8b4924bf2654661ed3d95fd66a313eb87237597c628e4a031f40a48df4b2a70c8b4924bf2654661ed3d95fd66a313eb87237597c628e4a0310000'

    let script = new btc.Script(`OP_OVER OP_PUSHDATA1 128 0x${ePreimagePrefix.toString('hex')} OP_SWAP OP_CAT OP_SHA256 OP_OVER OP_1 OP_CAT OP_EQUALVERIFY 32 0x${Gx.toString('hex')} OP_DUP OP_2 OP_ROLL OP_2 OP_CAT OP_CAT OP_SWAP OP_CHECKSIGVERIFY OP_TOALTSTACK 31 0x${paymentOut.toBufferWriter().toBuffer().toString('hex')} OP_SWAP OP_CAT OP_CAT OP_SHA256 OP_SWAP OP_CAT OP_CAT OP_CAT OP_CAT OP_SIZE 2 0xd200 OP_EQUALVERIFY 66 0x${preimagePrefix} OP_SWAP OP_CAT OP_SHA256 OP_FROMALTSTACK OP_EQUAL`)

    // For tapscript spends, we need to convert this script into a 'tapleaf'.
    const tapleaf = Tap.encodeScript(script.toBuffer())
    // Generate a tapkey that includes our leaf script. Also, create a merlke proof 
    // (cblock) that targets our leaf and proves its inclusion in the tapkey.
    const [tpubkey, cblock] = Tap.getPubKey(pubkey.toString(), { target: tapleaf })


    const scripP2TR = new btc.Script(`OP_1 32 0x${tpubkey}}`)

    // Fetch UTXO's for address
    const utxos = await fetchP2WPKHUtxos(addrP2WPKH)

    const tx0 = new btc.Transaction()
        .from(utxos)
        .addOutput(new btc.Transaction.Output({
            satoshis: 6000,
            script: scripP2TR
        }))
        .change(addrP2WPKH)
        .feePerByte(10)
        .sign(seckey)

    console.log('tx0 (serialized):', tx0.uncheckedSerialize())

    ////// UNLOCKING TX //////
    const utxoP2TR = {
        txId: tx0.id,
        outputIndex: 0,
        script: scripP2TR,
        satoshis: 6000
    };

    const tx1 = new btc.Transaction()
        .from(utxoP2TR)
        .to(
            [
                {
                    address:  addrP2WPKH,
                    satoshis: 546
                },
                {
                    address:  addrP2WPKH,
                    satoshis: 1000
                },
                {
                    address:  addrP2WPKH,
                    satoshis: 600
                }
            ]
        )

    // Mutate tx1 until e ends with 0x01.
    let e, eBuff, sighash;
    while (true) {
        sighash = getSigHash(tx1, Buffer.from(tapleaf, 'hex'), 0)
        e = await getE(sighash.hash)
        eBuff = e.toBuffer(32)
        const eLastByte = eBuff[eBuff.length - 1]
        if (eLastByte == 1) {
            break;
        }
        tx1.nLockTime += 1
    }

    const _e = eBuff.slice(0, eBuff.length - 1) // e' - e without last byte
    const preimageParts = splitSighashPreimage(sighash.preimage)

    const witnesses = [
        Buffer.concat([preimageParts.txVersion, preimageParts.nLockTime]),
        Buffer.concat([preimageParts.hashPrevouts, preimageParts.hashSpentAmounts]),
        Buffer.concat([preimageParts.hashScripts, preimageParts.hashSequences]),
        Buffer.concat([preimageParts.spendType, preimageParts.inputNumber, preimageParts.tapleafHash, preimageParts.keyVersion, preimageParts.codeseparatorPosition]),
        Buffer.concat([tx1.outputs[0].toBufferWriter().toBuffer()]),
        Buffer.concat([tx1.outputs[2].toBufferWriter().toBuffer()]),
        sighash.hash,
        _e,
        script.toBuffer(),
        Buffer.from(cblock, 'hex')
    ]
    tx1.inputs[0].witnesses = witnesses

    console.log('tx1 (serialized):', tx1.uncheckedSerialize())

    // Run locally
    const interpreter = new btc.Script.Interpreter()
    const flags = btc.Script.Interpreter.SCRIPT_VERIFY_WITNESS | btc.Script.Interpreter.SCRIPT_VERIFY_TAPROOT
    const res = interpreter.verify(new btc.Script(''), tx0.outputs[0].script, tx1, 0, flags, witnesses, 6000)
    console.log('Local execution success:', res)
}

main().catch(error => console.error('Error in main function:', error));
