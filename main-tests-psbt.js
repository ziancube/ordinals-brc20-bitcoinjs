const bitcoin = require('bitcoinjs-lib');
const ordinalsBitcoinjs = require('./src/ordinals-bitcoinjs')
const fs = require('fs')


const {
    createCommitTxData,
    createTextInscription,
    toXOnly,
  } = ordinalsBitcoinjs


// mock other user mnemonic

const ecc = require('tiny-secp256k1')
const { BIP32Factory } = require('bip32')
const bip32 = BIP32Factory(ecc)
const bip39 = require('bip39');
bitcoin.initEccLib(ecc);
// a random mnemonic
const mnemonic = `screen wagon below bronze rhythm sample wheel expire beyond tilt horror draft`;
const seed = bip39.mnemonicToSeedSync(mnemonic);
const root = bip32.fromSeed(seed);
console.log(root.fingerprint.toString('hex'));

const tweakHash = (pk, h) => bitcoin.crypto.taggedHash('TapTweak', Buffer.concat(h ? [pk, h] : [pk]))
const internal = root.derivePath("m/86'/0'/0'/0/0");
const pk = internal.publicKey
const out = internal.tweak(tweakHash(toXOnly(pk)))
const payment = bitcoin.payments.p2tr({ pubkey: toXOnly(out.publicKey) })
const script = payment.output
console.log("pk: ", pk.toString('hex'))
console.log("script: ", script.toString('hex'))
console.log("address: ",payment.address)

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

    // add other user inputs
    // 0200000001d2d36ee0c1e05cb0403f683b8fa08ce92e63b911839ac3e8bcba35cc792d2511000000006a4730440220329f165d778a060edda44489db6994dcd62d482d7eb0a16913345fc840a8522202202f9cc1526c027615371fafbe08adfcb2e121873a625f8ea214f146cf690b9ecf012103d534107f17143fd2d03476377a80a81fa9435d418d7cd0792e7547271f25d86ffdffffff02a00f0000000000001976a914c66a0b8d464c7da116964638e03b37283744ebe688ac0b0000000000000017a914d58582358f4c0c6c5625566de9be307dd617af4e8700000000
    psbt.addInput({
        hash: "93aa9299faf83ca8873d77a68025e4af3610b237a4e7c6dbaea896fbffc8347e",
        index: 0,
        nonWitnessUtxo: Buffer.from("0200000001d2d36ee0c1e05cb0403f683b8fa08ce92e63b911839ac3e8bcba35cc792d2511000000006a4730440220329f165d778a060edda44489db6994dcd62d482d7eb0a16913345fc840a8522202202f9cc1526c027615371fafbe08adfcb2e121873a625f8ea214f146cf690b9ecf012103d534107f17143fd2d03476377a80a81fa9435d418d7cd0792e7547271f25d86ffdffffff02a00f0000000000001976a914c66a0b8d464c7da116964638e03b37283744ebe688ac0b0000000000000017a914d58582358f4c0c6c5625566de9be307dd617af4e8700000000", "hex"),
        bip32Derivation: [
            {
                masterFingerprint: Buffer.from("8d2ef997", 'hex'),
                pubkey: Buffer.from("024de6e2233189426256a50d067c814c6a7cc44c30f972c373d121728a17375eba", "hex"),
                path: "m/44'/0'/0'/0/0",
            }
        ]
    })

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
    fs.writeFileSync("p2pkh.psbt", psbt.toBase64())
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

    // 0200000001d2d36ee0c1e05cb0403f683b8fa08ce92e63b911839ac3e8bcba35cc792d2511000000006a47304402207633c107a7d284338ca00433e9444fa821f45658776340928a8f8f5519977e5c022067b886f1fac4f4c77fc76d85f4365113dd993a64397637b7db4d68133c254a78012103d534107f17143fd2d03476377a80a81fa9435d418d7cd0792e7547271f25d86ffdffffff02a00f0000000000001600142cabeb97a530807f7756a4b61fcc08f464385d510b0000000000000017a914d58582358f4c0c6c5625566de9be307dd617af4e8700000000
    psbt.addInput({
        hash: "eb4f6be889395eb55a6a34c2146bddcea69c57145fc2b5de6822b4e880020237",
        index: 0,
        nonWitnessUtxo: Buffer.from("0200000001d2d36ee0c1e05cb0403f683b8fa08ce92e63b911839ac3e8bcba35cc792d2511000000006a47304402207633c107a7d284338ca00433e9444fa821f45658776340928a8f8f5519977e5c022067b886f1fac4f4c77fc76d85f4365113dd993a64397637b7db4d68133c254a78012103d534107f17143fd2d03476377a80a81fa9435d418d7cd0792e7547271f25d86ffdffffff02a00f0000000000001600142cabeb97a530807f7756a4b61fcc08f464385d510b0000000000000017a914d58582358f4c0c6c5625566de9be307dd617af4e8700000000", "hex"),
        witnessUtxo: {
            script: Buffer.from("00142cabeb97a530807f7756a4b61fcc08f464385d51", 'hex'),
            value: 4000,
        },
        bip32Derivation: [
            {
                masterFingerprint: Buffer.from("8d2ef997", 'hex'),
                pubkey: Buffer.from("03094aa2af98217df0815fc4f4360cb2404a28fa2d9c905d9f576366465396c340", "hex"),
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
    fs.writeFileSync("p2wpkh.psbt", psbt.toBase64())    
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

    // 0200000001d2d36ee0c1e05cb0403f683b8fa08ce92e63b911839ac3e8bcba35cc792d2511000000006a4730440220611aec05c9e16fae584e8bb137c18ab44ef96c74dfc73acd5f1eef0936349db50220140d6de592adcdcfceee2e67124c143221ce8c5c2091697a795b905a05af458c012103d534107f17143fd2d03476377a80a81fa9435d418d7cd0792e7547271f25d86ffdffffff02a00f00000000000017a914af3fea4b016eedd64e5537ccdba9b81c08ffcacc870b0000000000000017a914d58582358f4c0c6c5625566de9be307dd617af4e8700000000
    psbt.addInput({
        hash: "385bf78cbbc0234dab6ff73b8a7ba9fc102f0856cd3abd56bbfbd5168ebafe82",
        index: 0,
        nonWitnessUtxo: Buffer.from("0200000001d2d36ee0c1e05cb0403f683b8fa08ce92e63b911839ac3e8bcba35cc792d2511000000006a4730440220611aec05c9e16fae584e8bb137c18ab44ef96c74dfc73acd5f1eef0936349db50220140d6de592adcdcfceee2e67124c143221ce8c5c2091697a795b905a05af458c012103d534107f17143fd2d03476377a80a81fa9435d418d7cd0792e7547271f25d86ffdffffff02a00f00000000000017a914af3fea4b016eedd64e5537ccdba9b81c08ffcacc870b0000000000000017a914d58582358f4c0c6c5625566de9be307dd617af4e8700000000", 'hex'),
        bip32Derivation: [
            {
                masterFingerprint: Buffer.from("8d2ef997", 'hex'),
                pubkey: Buffer.from("03930344409ed17ad13aced7e36b7c007ba7fd1c15facab3351e2ed4d22cefa89f", "hex"),
                path: "m/49'/0'/0'/0/0",
            }
        ]
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
    fs.writeFileSync('p2wpkh-p2sh.psbt', psbt.toBase64())
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
    
    // 0200000001d2d36ee0c1e05cb0403f683b8fa08ce92e63b911839ac3e8bcba35cc792d2511000000006a473044022001a331d12711278e3e7f796d1270cf7213d0a9db26cc4076dc7295e307c5065e02201b8d527e410792dc92210a4af81978db8eeb1a9c03108c978ac039624615821a012103d534107f17143fd2d03476377a80a81fa9435d418d7cd0792e7547271f25d86ffdffffff02a00f000000000000225120cba7f01938330367655743ea1b4be46b6dde58c7f08e8d36aba93df1b70102b10b0000000000000017a914d58582358f4c0c6c5625566de9be307dd617af4e8700000000
    psbt.addInput({
        hash: "4a7f96aaaa5b7f615362db59c9e159fb2e9a1ec568839d8af1534aa0d58c5a21",
        index: 0,
        witnessUtxo: {
            script: Buffer.from("5120cba7f01938330367655743ea1b4be46b6dde58c7f08e8d36aba93df1b70102b1", "hex"),
            value: 4000,
        },
        tapBip32Derivation: [
            {
                masterFingerprint: Buffer.from("8d2ef997", 'hex'),
                pubkey: Buffer.from("c16ba46f15ff8658b77cf10d502d8c61d5d412785fc1bd7492d2c0be5fea8945", "hex"),
                path: "m/86'/0'/0'/0/0",
                leafHashes: []
            },
        ],
        tapInternalKey: toXOnly(Buffer.from("03c16ba46f15ff8658b77cf10d502d8c61d5d412785fc1bd7492d2c0be5fea8945", 'hex')),
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
    fs.writeFileSync('p2tr.psbt', psbt.toBase64())
}

function brc20() {
    // 86'
    var psbt = new bitcoin.Psbt({network: bitcoin.networks.bitcoin});

    // deploy
    const deploy = { 
        "p": "brc-20",
        "op": "deploy",
        "tick": "zian",
        "max": "21000000",
        "lim": "1000"
    }
    const xpk = toXOnly(Buffer.from("03975efe3b98e44ebc274316d45fd43080a8486dd95a692963b3c78763bf1670a5", 'hex'))
    const inscription = createTextInscription({ text: JSON.stringify(deploy)})
      // m/86'/0'/0'/0/0 script path spending
    const txData = createCommitTxData({
        publicKey: Buffer.from("03975efe3b98e44ebc274316d45fd43080a8486dd95a692963b3c78763bf1670a5", 'hex'), 
        inscription,
        network: bitcoin.networks.bitcoin
    })
    // console.log(txData)

    // 0200000001d2d36ee0c1e05cb0403f683b8fa08ce92e63b911839ac3e8bcba35cc792d2511000000006a47304402202d7945d91c1d5624e9247d88aa2ab09f605cd03a9ce400e9c92b770851a8a12e0220793ba631493f62478c94030d2ac59133c2e0521ef52ea5329b3c86faed8527f3012103d534107f17143fd2d03476377a80a81fa9435d418d7cd0792e7547271f25d86ffdffffff01084c010000000000225120e751e8d1e28c687781b1fd294e7f3ba24bfbf2e3ebd87ec19bc9cdc3729619b500000000
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
                pubkey: xpk,
                path: "m/86'/0'/0'/0/0",
                leafHashes: [],
            },
        ],
        tapInternalKey: xpk,
    });
    psbt.addOutput({
        address: txData.revealAddress,
        value: 84000
    })

    //部署交易，在外部看来就是一个普通的p2tr交易
    console.log("brc20 deploy psbt:")
    console.log(psbt.toBase64())
    
    // use device sign deploy result:
    // const signed = 'cHNidP8BAF4CAAAAAVfhCbuhvXrF8SSJc8oAkKzCXZkmnCS9Dao18Xe7/jqZAAAAAAD/////ASBIAQAAAAAAIlEg5ve1POcXT2edGCw3QC9AhRLB2LUMa7EoIC3spaDn1ZYAAAAAAAEBKwhMAQAAAAAAIlEg51Ho0eKMaHeBsf0pTn87okv78uPr2H7Bm8nNw3KWGbUBCEIBQHuYkixGjx1/lTDEE3F1aREHw3ASPxborbaeIlHaXMJ/8XvsLv7VTgooMesux8oIyhaBIJ8QZHjKqASkxhGunDoAAA=='
    // psbt = bitcoin.Psbt.fromBase64(signed)
    // const tx = psbt.extractTransaction()
    // console.log(tx.toHex())

    // 
    // 0200000000010157e109bba1bd7ac5f1248973ca0090acc25d99269c24bd0daa35f177bbfe3a990000000000ffffffff012048010000000000225120e6f7b53ce7174f679d182c37402f408512c1d8b50c6bb128202deca5a0e7d59601407b98922c468f1d7f9530c4137175691107c370123f16e8adb69e2251da5cc27ff17bec2efed54e0a2831eb2ec7ca08ca1681209f106478caa804a4c611ae9c3a00000000
    psbt = new bitcoin.Psbt({network: bitcoin.networks.bitcoin});
    psbt.addInput({
        hash: "fbbe306264d49750db1160a9c3570493f5c45718d1fd1ba3828e93ead26769d4",
        index: 0,
        witnessUtxo: {
            script: Buffer.from("5120e6f7b53ce7174f679d182c37402f408512c1d8b50c6bb128202deca5a0e7d596", "hex"),
            value: 84000,
        },
        tapBip32Derivation: [
            {
                masterFingerprint: Buffer.from("f1c149f5", 'hex'),
                pubkey: xpk,
                path: "m/86'/0'/0'/0/0",
                leafHashes: [],
            },
        ],
        tapInternalKey: xpk,
        tapLeafScript: [{
            leafVersion: 0xc0,
            script: txData.outputScript, // compiled txData.script
            controlBlock: Buffer.from(txData.cblock, 'hex')
        }]
    })

    psbt.addOutput({
        address: "bc1pgfyvjaml37u46tlg94vlhnfuc64k9exew4xyxwu3gkhy2tddxqesukh7s2",
        value: 40000,
    });
    console.log("brc20 tx psbt:")
    console.log(psbt.toBase64())
    fs.writeFileSync("brc20.psbt", psbt.toBase64())
    console.log(txData.scriptTaproot.output.toString("hex"))
}

// main().catch(console.error);

p2pkh()
p2wpkh()
p2wpkh_p2sh()
p2tr()
brc20()