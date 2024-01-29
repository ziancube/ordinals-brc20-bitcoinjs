const bitcoin = require('bitcoinjs-lib');
const bip39 = require('bip39');
const ecc = require('tiny-secp256k1')
const { BIP32Factory } = require('bip32')
const bip32 = BIP32Factory(ecc)
bitcoin.initEccLib(ecc);
const ordinalsBitcoinjs = require('./src/ordinals-bitcoinjs')

const {
    ECPair,
    createRevealTx,
    createCommitTxData,
    witnessStackToScriptWitness,
    createTextInscription,
    toXOnly,
  } = ordinalsBitcoinjs

const network = bitcoin.networks.testnet
const mnemonic = `gauge hole clog property soccer idea cycle stadium utility slice hold chief`;
const seed = bip39.mnemonicToSeedSync(mnemonic);
const root = bip32.fromSeed(seed, network);
const origin_node = root.derivePath("m/86'/1'/0'/0/0");
const reveal_node = root.derivePath("m/86'/1'/0'/0/1");
const origin_keypair = ECPair.fromPrivateKey(origin_node.privateKey,{ network })
const origin_tweaked = tweakSigner(origin_keypair, { network })
const reveal_keypair = ECPair.fromPrivateKey(reveal_node.privateKey,{ network })
const deploy_json = { 
    "p": "brc-20",
    "op": "deploy",
    "tick": "zian",
    "max": "21000000",
    "lim": "1000"
  }
function tweakSigner(signer, opts = {}) {
    let privateKey = signer.privateKey;
    if (!privateKey) {
        throw new Error('Private key is required for tweaking signer!');
    }
    if (signer.publicKey[0] === 3) {
        privateKey = ecc.privateNegate(privateKey);
    }
    const tweakedPrivateKey = ecc.privateAdd(privateKey, tapTweakHash(toXOnly(signer.publicKey), opts.tweakHash));
    if (!tweakedPrivateKey) {
        throw new Error('Invalid tweaked private key!');
    }
    return ECPair.fromPrivateKey(Buffer.from(tweakedPrivateKey), {
        network: opts.network,
    });
}

function tapTweakHash(pubKey, h) {
    return bitcoin.crypto.taggedHash('TapTweak', Buffer.concat(h ? [pubKey, h] : [pubKey]));
}

async function main() {
    origin_address = bitcoin.payments.p2tr({ internalPubkey: toXOnly(origin_node.publicKey), network }).address
    console.log(origin_address);
    //create commit data
    const inscription = createTextInscription({ text: JSON.stringify(deploy_json)})
    const commitTxData = createCommitTxData({publicKey: reveal_keypair.publicKey, inscription })
    const reveal_address = commitTxData.revealAddress
    const dust = 546
    const txSize = 600 + Math.floor(inscription.content.length / 4)
    const feeRate = 1
    const minersFee = txSize * feeRate
    const requiredAmount = 550 + minersFee + dust


    //create commit tx
    const commitTx = new bitcoin.Psbt({ network })
    commitTx.addInput({
        hash: '11252d79cc35babce8c39a8311b9632ee98ca08f3b683f40b05ce0c1e06ed3d2', 
        index: 0,
        witnessUtxo: {
            script: Buffer.from("5120b9df646724f062a5fc0dff79d4872d84c18d0b2908aa613bbe284a3ecdd07ead",'hex'),
            value: 549,
        },
        tapInternalKey: toXOnly(origin_node.publicKey),
    })
    commitTx.addInput({
        hash: 'abe1db4bc4ca7ba2f3bd6a8112f1a800d616a3940bee5fdcb7847a665dd08ca2', 
        index: 4,
        witnessUtxo: {
            script: Buffer.from("5120b9df646724f062a5fc0dff79d4872d84c18d0b2908aa613bbe284a3ecdd07ead",'hex'),
            value: 1000,
        },
        tapInternalKey: toXOnly(origin_node.publicKey),
    })
    commitTx.addInput({
        hash: 'a86a2fc6ab8bdc5cc0ac7c005bdd1510e3fb17974d72a01813e34bd2e8f03bc7', 
        index: 12,
        witnessUtxo: {
            script: Buffer.from("5120b9df646724f062a5fc0dff79d4872d84c18d0b2908aa613bbe284a3ecdd07ead",'hex'),
            value: 1000,
        },
        tapInternalKey: toXOnly(origin_node.publicKey),
    })
    commitTx.addOutput({
        address: reveal_address,
        value: requiredAmount,
    })
    console.log("before sign:");
    console.log(commitTx.toHex());
    commitTx.signInput(0, origin_tweaked)
    commitTx.signInput(1, origin_tweaked)
    commitTx.signInput(2, origin_tweaked)
    console.log("after sign:");
    console.log(commitTx.toHex());
    console.log("after finalize: ");
    const commitRawTx = commitTx.finalizeAllInputs().extractTransaction()
    console.log(commitRawTx.toHex());


    //create reveal tx
    const toAddress = origin_address
    const commitTxResult = {
        txId: 'd699019616fd1add93ea2e9e1a26fc29c71bf38a93400aec7ebde6a32a82bc20',  //change to commitTxid
        sendUtxoIndex: 0,
        sendAmount: requiredAmount,
      }

    const revelRawTx = await createRevealTx({
        commitTxData,
        commitTxResult,
        toAddress,
        privateKey:reveal_node.privateKey,
        amount: dust,
      })
    
    console.log(revelRawTx.rawTx)
}

function p2pkh() {
    // 44'
    // 0200000001d2d36ee0c1e05cb0403f683b8fa08ce92e63b911839ac3e8bcba35cc792d2511000000006a473044022024a2b5b2a5b44720ad0a2cf555139cf77b30f31731fe4f2c099b51a80e6557f10220037261fca0645cd14b1bfa1f6af04116b23e65148a8887f18763421b6e21d494012103d534107f17143fd2d03476377a80a81fa9435d418d7cd0792e7547271f25d86ffdffffff01084c0100000000001976a914c3894f7def040a0ffc28c21c597ffc033b4c814388ac00000000
    const psbt = new bitcoin.Psbt({network: bitcoin.networks.bitcoin});
    psbt.addInput({
        hash: "66162062271900e9651c722bd468512718dfecdbabc966752c923acff938192f",
        index: 0,
        nonWitnessUtxo: Buffer.from("0200000001d2d36ee0c1e05cb0403f683b8fa08ce92e63b911839ac3e8bcba35cc792d2511000000006a473044022024a2b5b2a5b44720ad0a2cf555139cf77b30f31731fe4f2c099b51a80e6557f10220037261fca0645cd14b1bfa1f6af04116b23e65148a8887f18763421b6e21d494012103d534107f17143fd2d03476377a80a81fa9435d418d7cd0792e7547271f25d86ffdffffff01084c0100000000001976a914c3894f7def040a0ffc28c21c597ffc033b4c814388ac00000000", "hex"),
        bip32Derivation: [
            {
                masterFingerprint: Buffer.from("f1c149f5", 'hex'),
                pubkey: Buffer.from("03d534107f17143fd2d03476377a80a81fa9435d418d7cd0792e7547271f25d86f", "hex"),
                path: "m/44'/0'/0'/0/0",
            },
        ],
    });
    psbt.addOutput({
        address: "1HRTGYnPZKPijkywF1KpLLNezKdbgCVSY8",
        value: 84000,
    });
    psbt.addOutput({
        address: "1MPv9p2WaBajpEKAHFb15rNLPCvXYjSfze",
        bip32Derivation: [
            {
                masterFingerprint: Buffer.from("f1c149f5", 'hex'),
                pubkey: Buffer.from("023be6ce9366256bd49536ade4a9149818ba37748df4d5177f11ed6e9d7472aa4a", "hex"),
                path: "m/44'/0'/0'/0/2",
            },
        ],
        value: 500
    });
    console.log("p2pkh => p2pkh tx:")
    console.log(psbt.toBase64())
}


function p2wpkh() {
    // 84'
    // 0200000001d2d36ee0c1e05cb0403f683b8fa08ce92e63b911839ac3e8bcba35cc792d2511000000006b483045022100ab921547b5e5f44708c10535f97633bddb40728e9b3e5d28312ce13fb8573a5f02204fe50495d9dac6a9071860f8080eb0a41bd73dad5000e795df1e6ed1e4e87421012103d534107f17143fd2d03476377a80a81fa9435d418d7cd0792e7547271f25d86ffdffffff01084c010000000000160014709956a32e2bf61f19a07782d173e7a568359b4300000000
    const psbt = new bitcoin.Psbt({network: bitcoin.networks.bitcoin});
    psbt.addInput({
        hash: "b7676d3b62e95fda97aea01065619c588d26876309905a0f95e00c9f98493b37",
        index: 0,
        nonWitnessUtxo: Buffer.from("0200000001d2d36ee0c1e05cb0403f683b8fa08ce92e63b911839ac3e8bcba35cc792d2511000000006b483045022100ab921547b5e5f44708c10535f97633bddb40728e9b3e5d28312ce13fb8573a5f02204fe50495d9dac6a9071860f8080eb0a41bd73dad5000e795df1e6ed1e4e87421012103d534107f17143fd2d03476377a80a81fa9435d418d7cd0792e7547271f25d86ffdffffff01084c010000000000160014709956a32e2bf61f19a07782d173e7a568359b4300000000",'hex'),
        witnessUtxo: {
            script: Buffer.from("0014709956a32e2bf61f19a07782d173e7a568359b43", 'hex'),
            value: 85000,
        },
        bip32Derivation: [
            {
                masterFingerprint: Buffer.from("f1c149f5", 'hex'),
                pubkey: Buffer.from("021bacf967f39cce551b990e7e5c2beb9888e4df8dc086b476bc831fc57e696797", "hex"),
                path: "m/84'/0'/0'/0/0",
            },
        ],
    });
    psbt.addOutput({
        address: "bc1qkqz0tlvd3quptynjs07t7zmf3sdrupchdhxu8r",
        value: 84000,
    });
    psbt.addOutput({
        address: "bc1qkexhyr7l3ceevzs52u5v9jj7krvxdfsu03yt8n",
        bip32Derivation: [
            {
                masterFingerprint: Buffer.from("f1c149f5", 'hex'),
                pubkey: Buffer.from("023f24aad950e3e9346dbf805e430ff988ea2affb10c5b7a44856714988022c14a", "hex"),
                path: "m/84'/0'/0'/0/2",
            },
        ],
        value: 500
    });
    console.log("p2wpkh => p2wpkh tx:")
    console.log(psbt.toBase64())
}

function p2wpkh_p2sh() {
    // 49'
    // 0200000001d2d36ee0c1e05cb0403f683b8fa08ce92e63b911839ac3e8bcba35cc792d2511000000006a473044022052d298dbee63d5f5cf3d1697c38aeb837ad28624b6fe573c6992a4cec8d9db6a022030f9165f9f53978a7cf6dcb0c82d5dc70ebb801b53bc7a38cbbc2b8dd7c2ea26012103d534107f17143fd2d03476377a80a81fa9435d418d7cd0792e7547271f25d86ffdffffff01084c01000000000017a914d58582358f4c0c6c5625566de9be307dd617af4e8700000000
    const psbt = new bitcoin.Psbt({network: bitcoin.networks.bitcoin});
    function getRedeemScript(pk) {
        let keyId = bitcoin.crypto.hash160(Buffer.from(pk, 'hex'))
        return Buffer.concat([Buffer.from("0014", 'hex'), keyId])
    }
    psbt.addInput({
        hash: "930b07d4feb5f5745bd4c183476e3ee1cdac84f023e6800551a32d70234c40b9",
        index: 0,
        nonWitnessUtxo: Buffer.from("0200000001d2d36ee0c1e05cb0403f683b8fa08ce92e63b911839ac3e8bcba35cc792d2511000000006a473044022052d298dbee63d5f5cf3d1697c38aeb837ad28624b6fe573c6992a4cec8d9db6a022030f9165f9f53978a7cf6dcb0c82d5dc70ebb801b53bc7a38cbbc2b8dd7c2ea26012103d534107f17143fd2d03476377a80a81fa9435d418d7cd0792e7547271f25d86ffdffffff01084c01000000000017a914d58582358f4c0c6c5625566de9be307dd617af4e8700000000", "hex"),
        // 也可以不传，不传的时候SDK会自己算
        redeemScript: getRedeemScript("027a28d603ddcbc769f96a1db223da0190c5808c7a1b74e67eeb44b463c33b71a2"),
        bip32Derivation: [
            {
                masterFingerprint: Buffer.from("f1c149f5", 'hex'),
                pubkey: Buffer.from("027a28d603ddcbc769f96a1db223da0190c5808c7a1b74e67eeb44b463c33b71a2", "hex"),
                path: "m/49'/0'/0'/0/0",
            },
        ],
    });
    psbt.addOutput({
        address: "3KWAbFcKxwpo3oUfQWgw5wahW6ifGTZgds",
        value: 84000,
    });
    psbt.addOutput({
        address: "3AbZe6adufnDUcax9jKxeGsguGzhDhUy6T",
        bip32Derivation: [
            {
                masterFingerprint: Buffer.from("f1c149f5", 'hex'),
                pubkey: Buffer.from("036b891ae565aaa581dc4e422a01d61923a8e7284259fea105f8097212671c9865", "hex"),
                path: "m/49'/0'/0'/0/2",
            },
        ],
        value: 500
    });
    console.log("p2wpkh-p2sh => p2wpkh-p2sh tx:")
    console.log(psbt.toBase64())
}

function p2tr() {
    // 86'
    // 0200000001d2d36ee0c1e05cb0403f683b8fa08ce92e63b911839ac3e8bcba35cc792d2511000000006a47304402202d7945d91c1d5624e9247d88aa2ab09f605cd03a9ce400e9c92b770851a8a12e0220793ba631493f62478c94030d2ac59133c2e0521ef52ea5329b3c86faed8527f3012103d534107f17143fd2d03476377a80a81fa9435d418d7cd0792e7547271f25d86ffdffffff01084c010000000000225120e751e8d1e28c687781b1fd294e7f3ba24bfbf2e3ebd87ec19bc9cdc3729619b500000000
    const psbt = new bitcoin.Psbt({network: bitcoin.networks.bitcoin});
    psbt.addInput({
        hash: "993afebb77f135aa0dbd249c26995dc2ac9000ca738924f1c57abda1bb09e157",
        index: 0,
        witnessUtxo: {
            script: Buffer.from("5120e751e8d1e28c687781b1fd294e7f3ba24bfbf2e3ebd87ec19bc9cdc3729619b5", "hex"),
            value: 85000,
        },
        tapBip32Derivation: [
            {
                masterFingerprint: Buffer.from("f1c149f5", 'hex'),
                pubkey: Buffer.from("975efe3b98e44ebc274316d45fd43080a8486dd95a692963b3c78763bf1670a5", "hex"),
                path: "m/86'/0'/0'/0/0",
                leafHashes: [],
            },
        ],
        tapInternalKey: toXOnly(Buffer.from("03975efe3b98e44ebc274316d45fd43080a8486dd95a692963b3c78763bf1670a5", 'hex')),
    });

    psbt.addOutput({
        address: "bc1pgfyvjaml37u46tlg94vlhnfuc64k9exew4xyxwu3gkhy2tddxqesukh7s2",
        value: 84000,
    });
    psbt.addOutput({
        address: "bc1prmayufcwckzj0mw6cpvmax8w3pylysk2t79g4n255lsvjxmq6faq5p6ymk",
        tapBip32Derivation: [
            {
                masterFingerprint: Buffer.from("f1c149f5", 'hex'),
                pubkey: Buffer.from("c2da22279327bc4545cd31076d2ebf278bd5fd00c56d800cfb725af7dbebff09", "hex"),
                path: "m/86'/0'/0'/0/2",
                leafHashes: []
            },
        ],
        tapInternalKey: toXOnly(Buffer.from("03c2da22279327bc4545cd31076d2ebf278bd5fd00c56d800cfb725af7dbebff09", 'hex')),
        value: 500
    });
    console.log("p2tr => p2tr tx:")
    console.log(psbt.toBase64())
}

// main().catch(console.error);

p2pkh()
p2wpkh()
p2wpkh_p2sh()
p2tr()