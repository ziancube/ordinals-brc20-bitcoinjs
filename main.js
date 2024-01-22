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
        hash: '38ec95ca6d255ef2f0f29b1deda5d228dc1d1a6278ad6e3acf0fa4ff27d10f15', 
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
    commitTx.signInput(0, origin_tweaked)
    commitTx.signInput(1, origin_tweaked)
    commitTx.signInput(2, origin_tweaked)
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

main().catch(console.error);