// Copyright 2019 CryptoGarage

#include "cfd/cfd_transaction.h"
#include "cfdcore/cfdcore_amount.h"
#include "cfdcore/cfdcore_ecdsa_adaptor.h"
#include "cfdcore/cfdcore_exception.h"
#include "cfddlc/cfddlc_transactions.h"
#include "wally_crypto.h"  // NOLINT
#include "gtest/gtest.h"

using cfd::Amount;
using cfd::core::AdaptorUtil;
using cfd::core::Address;
using cfd::core::ByteData;
using cfd::core::ByteData256;
using cfd::core::CfdException;
using cfd::core::CryptoUtil;
using cfd::core::ExtPrivkey;
using cfd::core::ExtPubkey;
using cfd::core::HashUtil;
using cfd::core::NetType;
using cfd::core::Privkey;
using cfd::core::Pubkey;
using cfd::core::SchnorrPubkey;
using cfd::core::SchnorrSignature;
using cfd::core::SchnorrUtil;
using cfd::core::ScriptUtil;
using cfd::core::SigHashAlgorithm;
using cfd::core::SigHashType;
using cfd::core::Txid;
using cfd::core::TxIn;
using cfd::core::TxOut;
using cfd::core::WitnessVersion;

using cfd::dlc::BatchPartyParams;
using cfd::dlc::DlcManager;
using cfd::dlc::DlcOutcome;
using cfd::dlc::PartyParams;
using cfd::dlc::TxInputInfo;

const std::vector<std::string> WIN_MESSAGES = {"WIN", "MORE"};
const std::vector<std::string> LOSE_MESSAGES = {"LOSE", "LESS"};
const std::vector<ByteData256> WIN_MESSAGES_HASH = {
  HashUtil::Sha256(WIN_MESSAGES[0]), HashUtil::Sha256(WIN_MESSAGES[1])};
const std::vector<ByteData256> LOSE_MESSAGES_HASH = {
  HashUtil::Sha256(LOSE_MESSAGES[0]), HashUtil::Sha256(LOSE_MESSAGES[1])};
const std::vector<ByteData256> WIN_MESSAGES_HASH_FEWER_MESSAGES = {
  HashUtil::Sha256(WIN_MESSAGES[0])};
const std::vector<ByteData256> LOSE_MESSAGES_HASH_FEWER_MESSAGES = {
  HashUtil::Sha256(LOSE_MESSAGES[0])};
const std::vector<std::vector<ByteData256>> MESSAGES_HASH = {
  WIN_MESSAGES_HASH, LOSE_MESSAGES_HASH};
const Privkey ORACLE_PRIVKEY(
  "ded9a76a0a77399e1c2676324118a0386004633f16245ad30d172b15c1f9e2d3");
const SchnorrPubkey ORACLE_PUBKEY = SchnorrPubkey::FromPrivkey(ORACLE_PRIVKEY);
const std::vector<Privkey> ORACLE_K_VALUES = {
  Privkey("be3cc8de25c50e25f69e2f88d151e3f63e99c3a44fed2bdd2e3ee70fe141c5c3"),
  Privkey("9e1bc6dc95ce931903cc2df67640cf6cca94ddd96aab0b847780d644e46cfae3")};
const std::vector<SchnorrPubkey> ORACLE_R_POINTS = {
  SchnorrPubkey::FromPrivkey(ORACLE_K_VALUES[0]),
  SchnorrPubkey::FromPrivkey(ORACLE_K_VALUES[1]),
};
const std::vector<SchnorrSignature> ORACLE_SIGNATURES = {
  SchnorrUtil::SignWithNonce(
    WIN_MESSAGES_HASH[0], ORACLE_PRIVKEY, ORACLE_K_VALUES[0]),
  SchnorrUtil::SignWithNonce(
    WIN_MESSAGES_HASH[1], ORACLE_PRIVKEY, ORACLE_K_VALUES[1])};
const Privkey LOCAL_FUND_PRIVKEY(
  "0000000000000000000000000000000000000000000000000000000000000001");
const Pubkey LOCAL_FUND_PUBKEY = LOCAL_FUND_PRIVKEY.GeneratePubkey();
const Privkey REMOTE_FUND_PRIVKEY(
  "0000000000000000000000000000000000000000000000000000000000000002");
const Pubkey REMOTE_FUND_PUBKEY = REMOTE_FUND_PRIVKEY.GeneratePubkey();
const Privkey LOCAL_FUND_PRIVKEY2(
  "0000000000000000000000000000000000000000000000000000000000000003");
const Pubkey LOCAL_FUND_PUBKEY2 = LOCAL_FUND_PRIVKEY2.GeneratePubkey();
const Privkey REMOTE_FUND_PRIVKEY2(
  "0000000000000000000000000000000000000000000000000000000000000004");
const Pubkey REMOTE_FUND_PUBKEY2 = REMOTE_FUND_PRIVKEY2.GeneratePubkey();
const Privkey LOCAL_INPUT_PRIVKEY(
  "0000000000000000000000000000000000000000000000000000000000000005");
const Pubkey LOCAL_INPUT_PUBKEY = LOCAL_INPUT_PRIVKEY.GeneratePubkey();
const Privkey REMOTE_INPUT_PRIVKEY(
  "0000000000000000000000000000000000000000000000000000000000000006");
const Pubkey REMOTE_INPUT_PUBKEY = REMOTE_INPUT_PRIVKEY.GeneratePubkey();
const Amount LOCAL_INPUT_AMOUNT = Amount::CreateByCoinAmount(50);
const Amount REMOTE_INPUT_AMOUNT = Amount::CreateByCoinAmount(50);
const Amount LOCAL_COLLATERAL_AMOUNT = Amount::CreateBySatoshiAmount(100000000);
const Amount REMOTE_COLLATERAL_AMOUNT =
  Amount::CreateBySatoshiAmount(100000000);
const Amount FUND_OUTPUT = Amount::CreateBySatoshiAmount(200000170);
const Amount FUND_OUTPUT1 = Amount::CreateBySatoshiAmount(200000168);
const Amount FUND_OUTPUT2 = Amount::CreateBySatoshiAmount(200000168);
const Amount WIN_AMOUNT = Amount::CreateBySatoshiAmount(199900000);
const Amount LOSE_AMOUNT = Amount::CreateBySatoshiAmount(100000);
const std::vector<TxInputInfo> LOCAL_INPUTS_INFO = {TxInputInfo{
  TxIn(
    Txid("83266d6b22a9babf6ee469b88fd0d3a0c690525f7c903aff22ec8ee44214604f"),
    0,
    0),
  108, 0}};
const std::vector<TxInputInfo> REMOTE_INPUTS_INFO = {TxInputInfo{
  TxIn(
    Txid("bc92a22f07ef23c53af343397874b59f5f8c0eb37753af1d1a159a2177d4bb98"),
    0,
    0),
  108, 0}};
const std::vector<TxInputInfo> LOCAL_INPUTS_INFO_SERIAL_ID = {TxInputInfo{
  TxIn(
    Txid("83266d6b22a9babf6ee469b88fd0d3a0c690525f7c903aff22ec8ee44214604f"),
    0,
    0),
  108, 3043}};
const std::vector<TxInputInfo> REMOTE_INPUTS_INFO_SERIAL_ID = {TxInputInfo{
  TxIn(
    Txid("bc92a22f07ef23c53af343397874b59f5f8c0eb37753af1d1a159a2177d4bb98"),
    0,
    0),
  108, 2302}};
const std::vector<TxIn> LOCAL_INPUTS = {TxIn(
  Txid("83266d6b22a9babf6ee469b88fd0d3a0c690525f7c903aff22ec8ee44214604f"),
  0,
  0)};
const std::vector<TxIn> REMOTE_INPUTS = {
  TxIn(
    Txid("bc92a22f07ef23c53af343397874b59f5f8c0eb37753af1d1a159a2177d4bb98"),
    0,
    0),
};
const Address
  LOCAL_CHANGE_ADDRESS("bcrt1qlgmznucxpdkp5k3ktsct7eh6qrc4tju7ktjukn");
const Address
  REMOTE_CHANGE_ADDRESS("bcrt1qvh2dvgjctwh4z5w7sc93u7h4sug0yrdz2lgpqf");
const Address LOCAL_FINAL_ADDRESS(
  NetType::kRegtest,
  WitnessVersion::kVersion0,
  Privkey("0000000000000000000000000000000000000000000000000000000000000007")
    .GeneratePubkey());
const Address LOCAL_FINAL_ADDRESS2(
  NetType::kRegtest,
  WitnessVersion::kVersion0,
  Privkey("0000000000000000000000000000000000000000000000000000000000000009")
    .GeneratePubkey());
const Address REMOTE_FINAL_ADDRESS(
  NetType::kRegtest,
  WitnessVersion::kVersion0,
  Privkey("0000000000000000000000000000000000000000000000000000000000000008")
    .GeneratePubkey());
const Address REMOTE_FINAL_ADDRESS2(
  NetType::kRegtest,
  WitnessVersion::kVersion0,
  Privkey("0000000000000000000000000000000000000000000000000000000000000010")
    .GeneratePubkey());

const PartyParams LOCAL_PARAMS = {
  LOCAL_FUND_PUBKEY,
  LOCAL_CHANGE_ADDRESS.GetLockingScript(),
  LOCAL_FINAL_ADDRESS.GetLockingScript(),
  LOCAL_INPUTS_INFO,
  LOCAL_INPUT_AMOUNT,
  LOCAL_COLLATERAL_AMOUNT,
  0,
  0};

const PartyParams REMOTE_PARAMS = {
  REMOTE_FUND_PUBKEY,
  REMOTE_CHANGE_ADDRESS.GetLockingScript(),
  REMOTE_FINAL_ADDRESS.GetLockingScript(),
  REMOTE_INPUTS_INFO,
  REMOTE_INPUT_AMOUNT,
  REMOTE_COLLATERAL_AMOUNT,
  0,
  0};

const PartyParams LOCAL_PARAMS_SERIAL_ID = {
  LOCAL_FUND_PUBKEY,
  LOCAL_CHANGE_ADDRESS.GetLockingScript(),
  LOCAL_FINAL_ADDRESS.GetLockingScript(),
  LOCAL_INPUTS_INFO_SERIAL_ID,
  LOCAL_INPUT_AMOUNT,
  LOCAL_COLLATERAL_AMOUNT,
  4593,
  3493};

const PartyParams REMOTE_PARAMS_SERIAL_ID = {
  REMOTE_FUND_PUBKEY,
  REMOTE_CHANGE_ADDRESS.GetLockingScript(),
  REMOTE_FINAL_ADDRESS.GetLockingScript(),
  REMOTE_INPUTS_INFO_SERIAL_ID,
  REMOTE_INPUT_AMOUNT,
  REMOTE_COLLATERAL_AMOUNT,
  2332,
  2039};

const BatchPartyParams LOCAL_BATCH_PARAMS = {
  {LOCAL_FUND_PUBKEY, LOCAL_FUND_PUBKEY2},
  LOCAL_CHANGE_ADDRESS.GetLockingScript(),
  {LOCAL_FINAL_ADDRESS.GetLockingScript(),
   LOCAL_FINAL_ADDRESS2.GetLockingScript()},
  LOCAL_INPUTS_INFO,
  LOCAL_INPUT_AMOUNT,
  {LOCAL_COLLATERAL_AMOUNT, LOCAL_COLLATERAL_AMOUNT},
  {0, 0},
  0};

const BatchPartyParams REMOTE_BATCH_PARAMS = {
  {REMOTE_FUND_PUBKEY, REMOTE_FUND_PUBKEY2},
  REMOTE_CHANGE_ADDRESS.GetLockingScript(),
  {REMOTE_FINAL_ADDRESS.GetLockingScript(),
   REMOTE_FINAL_ADDRESS2.GetLockingScript()},
  REMOTE_INPUTS_INFO,
  REMOTE_INPUT_AMOUNT,
  {REMOTE_COLLATERAL_AMOUNT, REMOTE_COLLATERAL_AMOUNT},
  {0, 0},
  0};

const ByteData FUND_TX_HEX(
  "020000000001024f601442e48eec22ff3a907c5f5290c6a0d3d08fb869e46ebfbaa9226b6d"
  "26830000000000ffffffff98bbd477219a151a1daf5377b30e8c5f9fb574783943f33ac523"
  "ef072fa292bc0000000000ffffffff03aac2eb0b000000002200209b984c7bae3efddc3a3f"
  "0a20ff81bfe89ed1fe07ff13e562149ee654bed845db2d10102401000000160014fa3629f3"
  "060b6c1a5a365c30bf66fa00f155cb9e2d1010240100000016001465d4d622585baf5151de"
  "860b1e7af58710f20da20247304402206d7181ec4d126c5e6bbf5ae65ee0297610f4f0d28a"
  "03ba6d782e651b136a6bd502200458622a92e2df148f90df85a2ebc402dd3aef43a10821c1"
  "6e8739426ba808a00121022f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8"
  "d569b240efe402473044022007e59c38bc05ac886b52f29147af2dd9f5a2f15188b02c0fc7"
  "7c2c42aa81bb7b022079da7f996b92ad4c5323c3e403c36dca967c7a3787cf7ac32b419f07"
  "5cbfdd1d012103fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a146029"
  "755600000000");
const ByteData BATCH_FUND_TX_HEX(
  "020000000001024f601442e48eec22ff3a907c5f5290c6a0d3d08fb869e46ebfbaa9226b6d26"
  "830000000000ffffffff98bbd477219a151a1daf5377b30e8c5f9fb574783943f33ac523ef07"
  "2fa292bc0000000000ffffffff04a8c2eb0b000000002200209b984c7bae3efddc3a3f0a20ff"
  "81bfe89ed1fe07ff13e562149ee654bed845dba8c2eb0b00000000220020257658f29a324d5c"
  "7ab66067a020b9e8485d1cf43b6609deba4e35a84d803bebc32e1a1e01000000160014fa3629"
  "f3060b6c1a5a365c30bf66fa00f155cb9ec32e1a1e0100000016001465d4d622585baf5151de"
  "860b1e7af58710f20da2024730440220465b4b4668a72d6ab474148a5e0541963d3b81cca21d"
  "c633c6c1784dc27c0dfe022003b4bcb22b41ca070b176566282e9699e9d7d68568dea582b207"
  "14de42ab498d0121022f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b2"
  "40efe40247304402205bc577dfc5830c2f65dd17a01e2bb6f99819a1de0989630ff680d1ae38"
  "5999d2022075b6fc581115d626cd7f3d27d52361a04e9264dc10b8ce1f429d40a0b829f17901"
  "2103fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a14602975560000000"
  "0");
const ByteData FUND_TX_WITH_SERIAL_ID_INPUTS_HEX(
  "0200000000010298bbd477219a151a1daf5377b30e8c5f9fb574783943f33ac523ef072fa2"
  "92bc0000000000ffffffff4f601442e48eec22ff3a907c5f5290c6a0d3d08fb869e46ebfba"
  "a9226b6d26830000000000ffffffff032d1010240100000016001465d4d622585baf5151de"
  "860b1e7af58710f20da22d10102401000000160014fa3629f3060b6c1a5a365c30bf66fa00"
  "f155cb9eaac2eb0b000000002200209b984c7bae3efddc3a3f0a20ff81bfe89ed1fe07ff13"
  "e562149ee654bed845db02473044022034f14f33aed317c10fc09177728ff652820a72f338"
  "99edfe4ce8ca361392fdb60220710988cd6acbbdc116e156594d7b4381f23d65e04c914f5d"
  "56f2461c8b9153cc012103fff97bd5755eeea420453a14355235d382f6472f8568a18b2f05"
  "7a14602975560247304402203655ac5589c11d41cf8f36c19f6e0f1ebecf7781c2db35bb98"
  "cccbec545ab1e10220400bf439532c971bc05bcd50e6f6216b7608481d532be751e48597b2"
  "ebe3d8390121022f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240"
  "efe400000000");
const ByteData FUND_TX_WITH_PREMIUM_HEX(
  "02000000024f601442e48eec22ff3a907c5f5290c6a0d3d08fb869e46ebfbaa9226b6d2683"
  "0000000000ffffffff98bbd477219a151a1daf5377b30e8c5f9fb574783943f33ac523ef07"
  "2fa292bc0000000000ffffffff04aac2eb0b000000002200209b984c7bae3efddc3a3f0a20"
  "ff81bfe89ed1fe07ff13e562149ee654bed845db6e890e2401000000160014fa3629f3060b"
  "6c1a5a365c30bf66fa00f155cb9e2d1010240100000016001465d4d622585baf5151de860b"
  "1e7af58710f20da2a0860100000000001600143104041af39ddcb0976f9ab6522001f096af"
  "e2ce00000000");
const Txid FUND_TX_ID(
  "c371cfe829d31c1d18f6f638047d44e5e2617d659ebdd43b83b04da32e864692");
const Txid FUND_TX_SERIAL_ID(
  "7f3b99048f96bceb3c1d2bef3057d19e46fc3eb0252d524d184892e9b6b6c904");

const ByteData CET_HEX(
  "02000000019246862ea34db0833bd4bd9e657d61e2e5447d0438f6f6181d1cd329e8cf71c3"
  "0000000000ffffffff02603bea0b000000001600145dedfbf9ea599dd4e3ca6a80b333c472"
  "fd0b3f69a0860100000000001600149652d86bedf43ad264362e6e6eba6eb7645081270000"
  "0000");
const ByteData CET_SERIAL_ID_HEX(
  "020000000104c9b6b6e99248184d522d25b03efc469ed15730ef2b1d3cebbc968f04993b7f"
  "0000000000ffffffff02a0860100000000001600149652d86bedf43ad264362e6e6eba6eb7"
  "64508127603bea0b000000001600145dedfbf9ea599dd4e3ca6a80b333c472fd0b3f690000"
  "0000");

const ByteData CET_HEX_SIGNED(
  "020000000001019246862ea34db0833bd4bd9e657d61e2e5447d0438f6f6181d1cd329e8cf"
  "71c30000000000ffffffff02603bea0b000000001600145dedfbf9ea599dd4e3ca6a80b333"
  "c472fd0b3f69a0860100000000001600149652d86bedf43ad264362e6e6eba6eb764508127"
  "0400473044022006560a7c24ce8688620cb1002b822c187858fba43607b286f09b9c02443b"
  "98f002207f8b1b6b120c0f4717f9f8c2cb739a400f94987dd48577ac4c4624c1477b969801"
  "473044022036d971f3da54303facb5fbf8dc7e9eef452cd94723eb6dc52f7aeee454791a00"
  "02204cf335114c47bae5e6dc2e00f566d1e37ec6fe25350fe797d48bff2573eeb548014752"
  "210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f817982102c6"
  "047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee552ae0000000"
  "0");
const ByteData CET_SERIAL_ID_HEX_SIGNED(
  "0200000000010104c9b6b6e99248184d522d25b03efc469ed15730ef2b1d3cebbc968f0499"
  "3b7f0000000000ffffffff02a0860100000000001600149652d86bedf43ad264362e6e6eba"
  "6eb764508127603bea0b000000001600145dedfbf9ea599dd4e3ca6a80b333c472fd0b3f69"
  "04004730440220486a85f310ea70af769896f23e20d7b187f11f4fdcdffb4248b152baeb24"
  "d96f022065e64eff95079e4e974f5c90407476bbbb916613c608f43043a0b3323fcba98701"
  "4730440220310f5d19a6c03dedddbb58a897dd815b98101bd12e60a055c5eef84184ec68b5"
  "02200b2cd18cc773c4c626de863483b7b6ac3f3b158e1a997f4dd814c5f60e5ed5f8014752"
  "210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f817982102c6"
  "047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee552ae0000000"
  "0");

uint32_t REFUND_LOCKTIME = 100;

const ByteData REFUND_HEX(
  "020000000001019246862ea34db0833bd4bd9e657d61e2e5447d0438f6f6181d1cd329e8cf"
  "71c30000000000feffffff0200e1f505000000001600145dedfbf9ea599dd4e3ca6a80b333"
  "c472fd0b3f6900e1f505000000001600149652d86bedf43ad264362e6e6eba6eb764508127"
  "040047304402204d7d24af8714835eead1143e5f589675c9e3b68d911ed5cbaaaa207586da"
  "c8e7022059a1febe7e12864a9ac59167510ffddfeed0f75920f611263e90b2068df52dbe01"
  "4730440220325b227c84d65a29d6f932f149af7fd6849237bc9d5dec09771d68f75dacb85e"
  "02202b8b0074f0804850ae4bdca21d139681d971117a669aae3385fb72acaa2feaee014752"
  "210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f817982102c6"
  "047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee552ae6400000"
  "0");
const ByteData BATCH_REFUND_HEX(
  "02000000000101f7b125244397e233997929b7baf6e7a94ecf3ee425537481dea9c9ab2b9be5"
  "d70000000000feffffff0200e1f505000000001600145dedfbf9ea599dd4e3ca6a80b333c472"
  "fd0b3f6900e1f505000000001600149652d86bedf43ad264362e6e6eba6eb764508127040047"
  "304402207050b5a85d992b7ac37e3f242b452577ebaad336dd338b9c8d334eb9338840f70220"
  "47d884d8f92022de3674f1c92914e68d0e6b0b62197aa5f00a5201f79ea9b4c4014730440220"
  "7107a317a4f2790e5216a39049e324f8cbe1c45222125413d171e63557d7b8d50220367fe84c"
  "4360b8518ee2a1bf6f12069f00d9513b3ba61e75f35a5bd5dc7e6b1c014752210279be667ef9"
  "dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f817982102c6047f9441ed7d6d30"
  "45406e95c07cd85c778e4b8cef3ca7abac09b95c709ee552ae64000000");
const ByteData BATCH_REFUND_HEX2(
  "02000000000101f7b125244397e233997929b7baf6e7a94ecf3ee425537481dea9c9ab2b9be5"
  "d70100000000feffffff0200e1f50500000000160014b46abf4d9e1746e33bcc39cea3de876c"
  "29c4adf300e1f5050000000016001460aa32549d990a09863b8fd4ce611ebd70bb310b040047"
  "3044022044c2c9c17b0974b8cac4d8942335e3b0d4bc349f6b018dfa9fa63e8751399f1c0220"
  "6903823f0e3b21508f364ed6824cc440a19825886da44f9fac9033fe96d82281014730440220"
  "249fccde2c0a1b0033f2e333aff3ab3cdd24a94aaadab75f358717127c285a3802202035a857"
  "ff73f0b28f5dfc921534e5f81519816e7b4c9cfa3c8b2c1d091c28c4014752210279be667ef9"
  "dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f817982102c6047f9441ed7d6d30"
  "45406e95c07cd85c778e4b8cef3ca7abac09b95c709ee552ae64000000");
const ByteData REFUND_SERIAL_ID_HEX(
  "020000000001019246862ea34db0833bd4bd9e657d61e2e5447d0438f6f6181d1cd329e8cf"
  "71c30100000000feffffff0200e1f505000000001600145dedfbf9ea599dd4e3ca6a80b333"
  "c472fd0b3f6900e1f505000000001600149652d86bedf43ad264362e6e6eba6eb764508127"
  "0400473044022068eaae53a3f01c0cd6cef5031b62c05688caf69ac152996b3c42421def65"
  "a5ba022048e64a816eeeab78f30e3472101ea12e5445ec3bb4ec070e3ea75b7ad663f77001"
  "47304402207d2b3604b4dae8dcadf3734a6ffab65a821b9a8f9eee9c6d75a223f480b864f8"
  "0220657fe4f5bf82a154122edbf68ac2c26bc463b24c9a0402989d74b6295f0f6311014752"
  "210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f817982102c6"
  "047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee552ae6400000"
  "0");
const ByteData REFUND_INPUTS_SERIAL_ID_HEX(
  "0200000000010104c9b6b6e99248184d522d25b03efc469ed15730ef2b1d3cebbc968f0499"
  "3b7f0200000000feffffff0200e1f505000000001600145dedfbf9ea599dd4e3ca6a80b333"
  "c472fd0b3f6900e1f505000000001600149652d86bedf43ad264362e6e6eba6eb764508127"
  "040047304402206b854782f4a7abed563ddad54cbfc30e0fe7dcf42cc2dd86bd9ced57897f"
  "08d20220356208c0cf30c14953d599feb0e5a9aabf11c36b5897ea5bc885cfa5415e2f1a01"
  "47304402202886aae45899892a57a7374b23cecf71fdc06501900fc4f77cdfa95977657683"
  "02206ca1db9835a45120a01f5f09ddc9592b2348c5343186a972ba82f28a49fc98eb014752"
  "210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f817982102c6"
  "047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee552ae6400000"
  "0");

const Address PREMIUM_DEST("bcrt1qxyzqgxhnnhwtp9m0n2m9ygqp7zt2lckwvxx4jq");
const Amount OPTION_PREMIUM = Amount::CreateBySatoshiAmount(100000);

TEST(DlcManager, FundTransactionTest) {
  // Arrange
  auto change = Amount::CreateBySatoshiAmount(4899999789);
  TxOut local_change_output = TxOut(change, LOCAL_CHANGE_ADDRESS);
  TxOut remote_change_output = TxOut(change, REMOTE_CHANGE_ADDRESS);

  // Act
  auto fund_tx = DlcManager::CreateFundTransaction(
    LOCAL_FUND_PUBKEY, REMOTE_FUND_PUBKEY, FUND_OUTPUT, LOCAL_INPUTS_INFO,
    local_change_output, REMOTE_INPUTS_INFO, remote_change_output);
  auto fund_tx2 = DlcManager::CreateFundTransaction(
    LOCAL_FUND_PUBKEY, REMOTE_FUND_PUBKEY, FUND_OUTPUT, LOCAL_INPUTS_INFO,
    local_change_output, REMOTE_INPUTS_INFO, remote_change_output);
  auto local_utxo_txid = LOCAL_INPUTS[0].GetTxid();
  auto local_utxo_vout = LOCAL_INPUTS[0].GetVout();
  auto remote_utxo_txid = REMOTE_INPUTS[0].GetTxid();
  auto remote_utxo_vout = REMOTE_INPUTS[0].GetVout();
  DlcManager::SignFundTransactionInput(
    &fund_tx, LOCAL_INPUT_PRIVKEY, local_utxo_txid, local_utxo_vout,
    LOCAL_INPUT_AMOUNT);
  DlcManager::SignFundTransactionInput(
    &fund_tx, REMOTE_INPUT_PRIVKEY, remote_utxo_txid, remote_utxo_vout,
    REMOTE_INPUT_AMOUNT);
  auto local_signature = DlcManager::GetRawFundingTransactionInputSignature(
    fund_tx, LOCAL_INPUT_PRIVKEY, local_utxo_txid, local_utxo_vout,
    LOCAL_INPUT_AMOUNT);
  auto remote_signature = DlcManager::GetRawFundingTransactionInputSignature(
    fund_tx, REMOTE_INPUT_PRIVKEY, remote_utxo_txid, remote_utxo_vout,
    REMOTE_INPUT_AMOUNT);
  DlcManager::AddSignatureToFundTransaction(
    &fund_tx2, local_signature, LOCAL_INPUT_PUBKEY, LOCAL_INPUTS[0].GetTxid(),
    LOCAL_INPUTS[0].GetVout());
  DlcManager::AddSignatureToFundTransaction(
    &fund_tx2, remote_signature, REMOTE_INPUT_PUBKEY,
    REMOTE_INPUTS[0].GetTxid(), REMOTE_INPUTS[0].GetVout());

  // Assert
  for (auto it = LOCAL_INPUTS.cbegin(); it != LOCAL_INPUTS.cend(); ++it) {
    EXPECT_NO_THROW(fund_tx.GetTxIn(it->GetTxid(), it->GetVout()));
  }

  for (auto it = REMOTE_INPUTS.cbegin(); it != REMOTE_INPUTS.cend(); ++it) {
    EXPECT_NO_THROW(fund_tx.GetTxIn(it->GetTxid(), it->GetVout()));
  }

  EXPECT_EQ(FUND_OUTPUT, fund_tx.GetTransaction().GetTxOut(0).GetValue());
  EXPECT_EQ(change, fund_tx.GetTransaction().GetTxOut(1).GetValue());
  EXPECT_EQ(change, fund_tx.GetTransaction().GetTxOut(2).GetValue());
  EXPECT_EQ(FUND_TX_HEX.GetHex(), fund_tx.GetTransaction().GetHex());
  EXPECT_TRUE(DlcManager::VerifyFundTxSignature(
    fund_tx, local_signature, LOCAL_INPUT_PUBKEY, local_utxo_txid,
    local_utxo_vout, LOCAL_INPUT_AMOUNT));
  EXPECT_TRUE(DlcManager::VerifyFundTxSignature(
    fund_tx, remote_signature, REMOTE_INPUT_PRIVKEY.GeneratePubkey(),
    remote_utxo_txid, remote_utxo_vout, REMOTE_INPUT_AMOUNT));
  EXPECT_EQ(fund_tx.GetHex(), fund_tx2.GetHex());
}

TEST(DlcManager, BatchFundTransactionTest) {
  // Arrange
  std::vector<Pubkey> local_fund_pubkeys = {
    LOCAL_FUND_PUBKEY, LOCAL_FUND_PUBKEY2};
  std::vector<Pubkey> remote_fund_pubkeys = {
    REMOTE_FUND_PUBKEY, REMOTE_FUND_PUBKEY2};
  std::vector<Amount> output_amounts = {FUND_OUTPUT1, FUND_OUTPUT2};
  std::vector<TxInputInfo> local_inputs_info = {LOCAL_INPUTS_INFO};
  std::vector<TxInputInfo> remote_inputs_info = {REMOTE_INPUTS_INFO};
  auto change = Amount::CreateBySatoshiAmount(4799999683);
  TxOut local_change_output = TxOut(change, LOCAL_CHANGE_ADDRESS);
  TxOut remote_change_output = TxOut(change, REMOTE_CHANGE_ADDRESS);
  std::vector<uint64_t> output_serial_ids = {0, 0};

  // Act
  auto batch_fund_tx = DlcManager::CreateBatchFundTransaction(
    local_fund_pubkeys, remote_fund_pubkeys, output_amounts, local_inputs_info,
    local_change_output, remote_inputs_info, remote_change_output);
  auto batch_fund_tx2 = DlcManager::CreateBatchFundTransaction(
    local_fund_pubkeys, remote_fund_pubkeys, output_amounts, local_inputs_info,
    local_change_output, remote_inputs_info, remote_change_output);
  auto local_utxo_txid = LOCAL_INPUTS[0].GetTxid();
  auto local_utxo_vout = LOCAL_INPUTS[0].GetVout();
  auto remote_utxo_txid = REMOTE_INPUTS[0].GetTxid();
  auto remote_utxo_vout = REMOTE_INPUTS[0].GetVout();
  DlcManager::SignFundTransactionInput(
    &batch_fund_tx, LOCAL_INPUT_PRIVKEY, local_utxo_txid, local_utxo_vout,
    LOCAL_INPUT_AMOUNT);
  DlcManager::SignFundTransactionInput(
    &batch_fund_tx, REMOTE_INPUT_PRIVKEY, remote_utxo_txid, remote_utxo_vout,
    REMOTE_INPUT_AMOUNT);
  auto local_signature = DlcManager::GetRawFundingTransactionInputSignature(
    batch_fund_tx, LOCAL_INPUT_PRIVKEY, local_utxo_txid, local_utxo_vout,
    LOCAL_INPUT_AMOUNT);
  auto remote_signature = DlcManager::GetRawFundingTransactionInputSignature(
    batch_fund_tx, REMOTE_INPUT_PRIVKEY, remote_utxo_txid, remote_utxo_vout,
    REMOTE_INPUT_AMOUNT);
  DlcManager::AddSignatureToFundTransaction(
    &batch_fund_tx2, local_signature, LOCAL_INPUT_PUBKEY,
    LOCAL_INPUTS[0].GetTxid(), LOCAL_INPUTS[0].GetVout());
  DlcManager::AddSignatureToFundTransaction(
    &batch_fund_tx2, remote_signature, REMOTE_INPUT_PUBKEY,
    REMOTE_INPUTS[0].GetTxid(), REMOTE_INPUTS[0].GetVout());

  // Assert
  for (auto it = LOCAL_INPUTS.cbegin(); it != LOCAL_INPUTS.cend(); ++it) {
    EXPECT_NO_THROW(batch_fund_tx.GetTxIn(it->GetTxid(), it->GetVout()));
  }

  for (auto it = REMOTE_INPUTS.cbegin(); it != REMOTE_INPUTS.cend(); ++it) {
    EXPECT_NO_THROW(batch_fund_tx.GetTxIn(it->GetTxid(), it->GetVout()));
  }

  EXPECT_EQ(
    FUND_OUTPUT1, batch_fund_tx.GetTransaction().GetTxOut(0).GetValue());
  EXPECT_EQ(change, batch_fund_tx.GetTransaction().GetTxOut(2).GetValue());
  EXPECT_EQ(change, batch_fund_tx.GetTransaction().GetTxOut(3).GetValue());
  EXPECT_EQ(
    BATCH_FUND_TX_HEX.GetHex(), batch_fund_tx.GetTransaction().GetHex());
  EXPECT_TRUE(DlcManager::VerifyFundTxSignature(
    batch_fund_tx, local_signature, LOCAL_INPUT_PUBKEY, local_utxo_txid,
    local_utxo_vout, LOCAL_INPUT_AMOUNT));
  EXPECT_TRUE(DlcManager::VerifyFundTxSignature(
    batch_fund_tx, remote_signature, REMOTE_INPUT_PRIVKEY.GeneratePubkey(),
    remote_utxo_txid, remote_utxo_vout, REMOTE_INPUT_AMOUNT));
  EXPECT_EQ(batch_fund_tx.GetHex(), batch_fund_tx2.GetHex());
}

TEST(DlcManager, CetTest) {
  // Arrange
  auto local_payout = Amount::CreateBySatoshiAmount(199900000);
  auto remote_payout = Amount::CreateBySatoshiAmount(100000);
  TxOut local_output(local_payout, LOCAL_FINAL_ADDRESS);
  TxOut remote_output(remote_payout, REMOTE_FINAL_ADDRESS);
  // Act
  auto cet =
    DlcManager::CreateCet(local_output, remote_output, FUND_TX_ID, 0, 0);

  auto fund_script = DlcManager::CreateFundTxLockingScript(
    LOCAL_FUND_PUBKEY, REMOTE_FUND_PUBKEY);
  auto local_adaptor_pair = DlcManager::CreateCetAdaptorSignature(
    cet, ORACLE_PUBKEY, {ORACLE_R_POINTS[0]}, LOCAL_FUND_PRIVKEY, fund_script,
    FUND_OUTPUT, {WIN_MESSAGES_HASH[0]});
  auto remote_adaptor_pair = DlcManager::CreateCetAdaptorSignature(
    cet, ORACLE_PUBKEY, {ORACLE_R_POINTS[0]}, REMOTE_FUND_PRIVKEY, fund_script,
    FUND_OUTPUT, {WIN_MESSAGES_HASH[0]});

  // Assert
  EXPECT_EQ(
    FUND_TX_ID.GetHex(), cet.GetTransaction().GetTxIn(0).GetTxid().GetHex());
  EXPECT_EQ(0, cet.GetTransaction().GetTxIn(0).GetVout());
  EXPECT_EQ(local_payout, cet.GetTransaction().GetTxOut(0).GetValue());
  EXPECT_TRUE(
    cet.GetTransaction().GetTxOut(0).GetLockingScript().IsP2wpkhScript());
  EXPECT_EQ(remote_payout, cet.GetTransaction().GetTxOut(1).GetValue());
  EXPECT_TRUE(
    cet.GetTransaction().GetTxOut(1).GetLockingScript().IsP2wpkhScript());
  EXPECT_EQ(CET_HEX.GetHex(), cet.GetHex());
  EXPECT_TRUE(DlcManager::VerifyCetAdaptorSignature(
    local_adaptor_pair, cet, LOCAL_FUND_PUBKEY, ORACLE_PUBKEY,
    {ORACLE_R_POINTS[0]}, fund_script, FUND_OUTPUT, {WIN_MESSAGES_HASH[0]}));
  EXPECT_TRUE(DlcManager::VerifyCetAdaptorSignature(
    remote_adaptor_pair, cet, REMOTE_FUND_PUBKEY, ORACLE_PUBKEY,
    {ORACLE_R_POINTS[0]}, fund_script, FUND_OUTPUT, {WIN_MESSAGES_HASH[0]}));

  DlcManager::SignCet(
    &cet, local_adaptor_pair.signature, {ORACLE_SIGNATURES[0]},
    REMOTE_FUND_PRIVKEY, fund_script, FUND_TX_ID, 0, FUND_OUTPUT);
  EXPECT_EQ(cet.GetHex(), CET_HEX_SIGNED.GetHex());
}

TEST(DlcManager, RefundTransactionTest) {
  // Arrange
  // Act
  auto refund_tx = DlcManager::CreateRefundTransaction(
    LOCAL_FINAL_ADDRESS.GetLockingScript(),
    REMOTE_FINAL_ADDRESS.GetLockingScript(),
    Amount::CreateBySatoshiAmount(100000000),
    Amount::CreateBySatoshiAmount(100000000), 100, FUND_TX_ID, 0);

  auto local_signature = DlcManager::GetRawRefundTxSignature(
    refund_tx, LOCAL_FUND_PRIVKEY, LOCAL_FUND_PUBKEY, REMOTE_FUND_PUBKEY,
    FUND_OUTPUT, FUND_TX_ID, 0);
  auto remote_signature = DlcManager::GetRawRefundTxSignature(
    refund_tx, REMOTE_FUND_PRIVKEY, LOCAL_FUND_PUBKEY, REMOTE_FUND_PUBKEY,
    FUND_OUTPUT, FUND_TX_ID, 0);
  DlcManager::AddSignaturesToRefundTx(
    &refund_tx, LOCAL_FUND_PUBKEY, REMOTE_FUND_PUBKEY,
    {local_signature, remote_signature}, FUND_TX_ID, 0);

  // Assert
  EXPECT_EQ(REFUND_HEX.GetHex(), refund_tx.GetHex());
  EXPECT_TRUE(DlcManager::VerifyRefundTxSignature(
    refund_tx, local_signature, LOCAL_FUND_PUBKEY, REMOTE_FUND_PUBKEY,
    FUND_OUTPUT, false, FUND_TX_ID, 0));
  EXPECT_TRUE(DlcManager::VerifyRefundTxSignature(
    refund_tx, remote_signature, LOCAL_FUND_PUBKEY, REMOTE_FUND_PUBKEY,
    FUND_OUTPUT, true, FUND_TX_ID, 0));
}

TEST(DlcManager, CreateDlcTransactions) {
  // Arrange
  std::vector<DlcOutcome> outcomes = {
    {WIN_AMOUNT, LOSE_AMOUNT}, {LOSE_AMOUNT, WIN_AMOUNT}};

  // Act
  auto dlc_transactions = DlcManager::CreateDlcTransactions(
    outcomes, LOCAL_PARAMS, REMOTE_PARAMS, REFUND_LOCKTIME, 1);
  auto fund_tx = dlc_transactions.fund_transaction;
  DlcManager::SignFundTransactionInput(
    &fund_tx, LOCAL_INPUT_PRIVKEY, LOCAL_INPUTS[0].GetTxid(), 0,
    LOCAL_INPUT_AMOUNT);
  DlcManager::SignFundTransactionInput(
    &fund_tx, REMOTE_INPUT_PRIVKEY, REMOTE_INPUTS[0].GetTxid(), 0,
    REMOTE_INPUT_AMOUNT);

  auto local_fund_signature =
    DlcManager::GetRawFundingTransactionInputSignature(
      fund_tx, LOCAL_INPUT_PRIVKEY, LOCAL_INPUTS[0].GetTxid(), 0,
      LOCAL_INPUT_AMOUNT);

  bool is_local_fund_signature_valid = DlcManager::VerifyFundTxSignature(
    fund_tx, local_fund_signature, LOCAL_INPUT_PUBKEY,
    LOCAL_INPUTS[0].GetTxid(), 0, LOCAL_INPUT_AMOUNT);

  auto remote_fund_signature =
    DlcManager::GetRawFundingTransactionInputSignature(
      fund_tx, REMOTE_INPUT_PRIVKEY, REMOTE_INPUTS[0].GetTxid(), 0,
      REMOTE_INPUT_AMOUNT);

  bool is_remote_fund_signature_valid = DlcManager::VerifyFundTxSignature(
    fund_tx, remote_fund_signature, REMOTE_INPUT_PUBKEY,
    REMOTE_INPUTS[0].GetTxid(), 0, REMOTE_INPUT_AMOUNT);

  auto refund_tx = dlc_transactions.refund_transaction;

  auto fund_tx_id = fund_tx.GetTransaction().GetTxid();

  auto local_refund_signature = DlcManager::GetRawRefundTxSignature(
    refund_tx, LOCAL_FUND_PRIVKEY, LOCAL_FUND_PUBKEY, REMOTE_FUND_PUBKEY,
    FUND_OUTPUT, fund_tx_id, 0);

  auto remote_refund_signature = DlcManager::GetRawRefundTxSignature(
    refund_tx, REMOTE_FUND_PRIVKEY, LOCAL_FUND_PUBKEY, REMOTE_FUND_PUBKEY,
    FUND_OUTPUT, fund_tx_id, 0);

  DlcManager::AddSignaturesToRefundTx(
    &refund_tx, LOCAL_FUND_PUBKEY, REMOTE_FUND_PUBKEY,
    {local_refund_signature, remote_refund_signature}, fund_tx_id, 0);

  bool is_local_refund_signature_valid = DlcManager::VerifyRefundTxSignature(
    refund_tx, local_refund_signature, LOCAL_FUND_PUBKEY, REMOTE_FUND_PUBKEY,
    FUND_OUTPUT, false, fund_tx_id, 0);

  bool is_remote_refund_signature_valid = DlcManager::VerifyRefundTxSignature(
    refund_tx, remote_refund_signature, LOCAL_FUND_PUBKEY, REMOTE_FUND_PUBKEY,
    FUND_OUTPUT, true, fund_tx_id, 0);

  auto cets = dlc_transactions.cets;
  auto nb_cet = cets.size();

  auto fund_script = DlcManager::CreateFundTxLockingScript(
    LOCAL_FUND_PUBKEY, REMOTE_FUND_PUBKEY);

  bool all_valid_cet_signatures = true;
  for (size_t i = 0; i < nb_cet; i++) {
    auto local_cet_adaptor_pair = DlcManager::CreateCetAdaptorSignature(
      cets[i], ORACLE_PUBKEY, {ORACLE_R_POINTS[0]}, LOCAL_FUND_PRIVKEY,
      fund_script, FUND_OUTPUT, {MESSAGES_HASH[i][0]});
    all_valid_cet_signatures &= DlcManager::VerifyCetAdaptorSignature(
      local_cet_adaptor_pair, cets[i], LOCAL_FUND_PUBKEY, ORACLE_PUBKEY,
      {ORACLE_R_POINTS[0]}, fund_script, FUND_OUTPUT, {MESSAGES_HASH[i][0]});
    auto remote_cet_adaptor_pair = DlcManager::CreateCetAdaptorSignature(
      cets[i], ORACLE_PUBKEY, {ORACLE_R_POINTS[0]}, LOCAL_FUND_PRIVKEY,
      fund_script, FUND_OUTPUT, {MESSAGES_HASH[i][0]});
    all_valid_cet_signatures &= DlcManager::VerifyCetAdaptorSignature(
      remote_cet_adaptor_pair, cets[i], LOCAL_FUND_PUBKEY, ORACLE_PUBKEY,
      {ORACLE_R_POINTS[0]}, fund_script, FUND_OUTPUT, {MESSAGES_HASH[i][0]});
  }

  auto local_cet_adaptor_pairs = DlcManager::CreateCetAdaptorSignatures(
    cets, ORACLE_PUBKEY, {ORACLE_R_POINTS[0]}, LOCAL_FUND_PRIVKEY, fund_script,
    FUND_OUTPUT, {{WIN_MESSAGES_HASH[0]}, {LOSE_MESSAGES_HASH[0]}});

  bool all_valid_cet_pair_batch = DlcManager::VerifyCetAdaptorSignatures(
    cets, local_cet_adaptor_pairs,
    {{WIN_MESSAGES_HASH[0]}, {LOSE_MESSAGES_HASH[0]}}, LOCAL_FUND_PUBKEY,
    ORACLE_PUBKEY, {ORACLE_R_POINTS[0]}, fund_script, FUND_OUTPUT);
  auto remote_cet_adaptor_pairs = DlcManager::CreateCetAdaptorSignatures(
    cets, ORACLE_PUBKEY, {ORACLE_R_POINTS[0]}, LOCAL_FUND_PRIVKEY, fund_script,
    FUND_OUTPUT, {{WIN_MESSAGES_HASH[0]}, {LOSE_MESSAGES_HASH[0]}});

  all_valid_cet_pair_batch &= DlcManager::VerifyCetAdaptorSignatures(
    cets, remote_cet_adaptor_pairs,
    {{WIN_MESSAGES_HASH[0]}, {LOSE_MESSAGES_HASH[0]}}, LOCAL_FUND_PUBKEY,
    ORACLE_PUBKEY, {ORACLE_R_POINTS[0]}, fund_script, FUND_OUTPUT);

  EXPECT_EQ(dlc_transactions.cets.size(), outcomes.size());
  EXPECT_EQ(FUND_TX_HEX.GetHex(), fund_tx.GetHex());
  EXPECT_TRUE(is_local_fund_signature_valid);
  EXPECT_TRUE(is_remote_fund_signature_valid);
  EXPECT_EQ(REFUND_HEX.GetHex(), refund_tx.GetHex());
  EXPECT_TRUE(is_local_refund_signature_valid);
  EXPECT_TRUE(is_remote_refund_signature_valid);
  EXPECT_TRUE(all_valid_cet_signatures);
  EXPECT_TRUE(all_valid_cet_pair_batch);
}

TEST(DlcManager, CreateBatchDlcTransactions) {
  // Arrange
  std::vector<DlcOutcome> outcomes = {
    {WIN_AMOUNT, LOSE_AMOUNT}, {LOSE_AMOUNT, WIN_AMOUNT}};
  std::vector<std::vector<DlcOutcome>> outcomes_batch = {outcomes, outcomes};

  // Act
  auto dlc_transactions = DlcManager::CreateBatchDlcTransactions(
    outcomes_batch, LOCAL_BATCH_PARAMS, REMOTE_BATCH_PARAMS, REFUND_LOCKTIME,
    1);
  auto fund_tx = dlc_transactions.fund_transaction;
  DlcManager::SignFundTransactionInput(
    &fund_tx, LOCAL_INPUT_PRIVKEY, LOCAL_INPUTS[0].GetTxid(), 0,
    LOCAL_INPUT_AMOUNT);
  DlcManager::SignFundTransactionInput(
    &fund_tx, REMOTE_INPUT_PRIVKEY, REMOTE_INPUTS[0].GetTxid(), 0,
    REMOTE_INPUT_AMOUNT);

  auto local_fund_signature =
    DlcManager::GetRawFundingTransactionInputSignature(
      fund_tx, LOCAL_INPUT_PRIVKEY, LOCAL_INPUTS[0].GetTxid(), 0,
      LOCAL_INPUT_AMOUNT);

  bool is_local_fund_signature_valid = DlcManager::VerifyFundTxSignature(
    fund_tx, local_fund_signature, LOCAL_INPUT_PUBKEY,
    LOCAL_INPUTS[0].GetTxid(), 0, LOCAL_INPUT_AMOUNT);

  auto remote_fund_signature =
    DlcManager::GetRawFundingTransactionInputSignature(
      fund_tx, REMOTE_INPUT_PRIVKEY, REMOTE_INPUTS[0].GetTxid(), 0,
      REMOTE_INPUT_AMOUNT);

  bool is_remote_fund_signature_valid = DlcManager::VerifyFundTxSignature(
    fund_tx, remote_fund_signature, REMOTE_INPUT_PUBKEY,
    REMOTE_INPUTS[0].GetTxid(), 0, REMOTE_INPUT_AMOUNT);

  auto refund_txs = dlc_transactions.refund_transactions;

  auto fund_tx_id = fund_tx.GetTransaction().GetTxid();

  bool all_valid_refund_signatures = true;

  for (size_t i = 0; i < refund_txs.size(); i++) {
    auto refund_tx = refund_txs[i];
    auto fund_vout = i;

    auto local_refund_signature = DlcManager::GetRawRefundTxSignature(
      refund_tx, LOCAL_FUND_PRIVKEY, LOCAL_FUND_PUBKEY, REMOTE_FUND_PUBKEY,
      FUND_OUTPUT, fund_tx_id, fund_vout);

    auto remote_refund_signature = DlcManager::GetRawRefundTxSignature(
      refund_tx, REMOTE_FUND_PRIVKEY, LOCAL_FUND_PUBKEY, REMOTE_FUND_PUBKEY,
      FUND_OUTPUT, fund_tx_id, fund_vout);

    DlcManager::AddSignaturesToRefundTx(
      &refund_tx, LOCAL_FUND_PUBKEY, REMOTE_FUND_PUBKEY,
      {local_refund_signature, remote_refund_signature}, fund_tx_id, fund_vout);

    all_valid_refund_signatures &= DlcManager::VerifyRefundTxSignature(
      refund_tx, local_refund_signature, LOCAL_FUND_PUBKEY, REMOTE_FUND_PUBKEY,
      FUND_OUTPUT, false, fund_tx_id, fund_vout);

    all_valid_refund_signatures &= DlcManager::VerifyRefundTxSignature(
      refund_tx, remote_refund_signature, LOCAL_FUND_PUBKEY, REMOTE_FUND_PUBKEY,
      FUND_OUTPUT, true, fund_tx_id, fund_vout);

    if (i == 0) {
      EXPECT_EQ(BATCH_REFUND_HEX.GetHex(), refund_tx.GetHex());
    } else {
      EXPECT_EQ(BATCH_REFUND_HEX2.GetHex(), refund_tx.GetHex());
    }
  }

  auto cets_list = dlc_transactions.cets_list;

  auto fund_script = DlcManager::CreateFundTxLockingScript(
    LOCAL_FUND_PUBKEY, REMOTE_FUND_PUBKEY);

  bool all_valid_cet_signatures = true;
  bool all_valid_cet_pair_batch = true;

  for (auto cets : cets_list) {
    for (size_t i = 0; i < cets.size(); i++) {
      auto local_cet_adaptor_pair = DlcManager::CreateCetAdaptorSignature(
        cets[i], ORACLE_PUBKEY, {ORACLE_R_POINTS[0]}, LOCAL_FUND_PRIVKEY,
        fund_script, FUND_OUTPUT, {MESSAGES_HASH[i][0]});
      all_valid_cet_signatures &= DlcManager::VerifyCetAdaptorSignature(
        local_cet_adaptor_pair, cets[i], LOCAL_FUND_PUBKEY, ORACLE_PUBKEY,
        {ORACLE_R_POINTS[0]}, fund_script, FUND_OUTPUT, {MESSAGES_HASH[i][0]});
      auto remote_cet_adaptor_pair = DlcManager::CreateCetAdaptorSignature(
        cets[i], ORACLE_PUBKEY, {ORACLE_R_POINTS[0]}, LOCAL_FUND_PRIVKEY,
        fund_script, FUND_OUTPUT, {MESSAGES_HASH[i][0]});
      all_valid_cet_signatures &= DlcManager::VerifyCetAdaptorSignature(
        remote_cet_adaptor_pair, cets[i], LOCAL_FUND_PUBKEY, ORACLE_PUBKEY,
        {ORACLE_R_POINTS[0]}, fund_script, FUND_OUTPUT, {MESSAGES_HASH[i][0]});
    }

    auto local_cet_adaptor_pairs = DlcManager::CreateCetAdaptorSignatures(
      cets, ORACLE_PUBKEY, {ORACLE_R_POINTS[0]}, LOCAL_FUND_PRIVKEY,
      fund_script, FUND_OUTPUT,
      {{WIN_MESSAGES_HASH[0]}, {LOSE_MESSAGES_HASH[0]}});

    all_valid_cet_pair_batch = DlcManager::VerifyCetAdaptorSignatures(
      cets, local_cet_adaptor_pairs,
      {{WIN_MESSAGES_HASH[0]}, {LOSE_MESSAGES_HASH[0]}}, LOCAL_FUND_PUBKEY,
      ORACLE_PUBKEY, {ORACLE_R_POINTS[0]}, fund_script, FUND_OUTPUT);

    auto remote_cet_adaptor_pairs = DlcManager::CreateCetAdaptorSignatures(
      cets, ORACLE_PUBKEY, {ORACLE_R_POINTS[0]}, LOCAL_FUND_PRIVKEY,
      fund_script, FUND_OUTPUT,
      {{WIN_MESSAGES_HASH[0]}, {LOSE_MESSAGES_HASH[0]}});

    all_valid_cet_pair_batch &= DlcManager::VerifyCetAdaptorSignatures(
      cets, remote_cet_adaptor_pairs,
      {{WIN_MESSAGES_HASH[0]}, {LOSE_MESSAGES_HASH[0]}}, LOCAL_FUND_PUBKEY,
      ORACLE_PUBKEY, {ORACLE_R_POINTS[0]}, fund_script, FUND_OUTPUT);

    EXPECT_EQ(cets.size(), outcomes.size());
  }

  EXPECT_EQ(BATCH_FUND_TX_HEX.GetHex(), fund_tx.GetHex());
  EXPECT_TRUE(is_local_fund_signature_valid);
  EXPECT_TRUE(is_remote_fund_signature_valid);
  // EXPECT_EQ(REFUND_HEX.GetHex(), refund_tx.GetHex());
  EXPECT_TRUE(all_valid_cet_signatures);
  EXPECT_TRUE(all_valid_refund_signatures);
  EXPECT_TRUE(all_valid_cet_pair_batch);
}

TEST(DlcManager, CreateCetTransactionNotEnoughInputTest) {
  // Arrange
  std::vector<DlcOutcome> outcomes = {
    {WIN_AMOUNT, LOSE_AMOUNT}, {LOSE_AMOUNT, WIN_AMOUNT}};

  auto local_params_short = LOCAL_PARAMS;
  local_params_short.input_amount = Amount::CreateBySatoshiAmount(1000);
  auto remote_params_short = LOCAL_PARAMS;
  remote_params_short.input_amount = Amount::CreateBySatoshiAmount(1000);
  // Act/Assert
  ASSERT_THROW(
    auto dlc_transactions = DlcManager::CreateDlcTransactions(
      outcomes, local_params_short, REMOTE_PARAMS, REFUND_LOCKTIME, 1),
    CfdException);
  ASSERT_THROW(
    auto dlc_transactions = DlcManager::CreateDlcTransactions(
      outcomes, remote_params_short, REMOTE_PARAMS, REFUND_LOCKTIME, 1),
    CfdException);
}

TEST(DlcManager, FundTransactionWithPremiumTest) {
  // Arrange
  auto local_change = Amount::CreateBySatoshiAmount(4899899758);
  auto remote_change = Amount::CreateBySatoshiAmount(4899999789);
  TxOut local_change_output = TxOut(local_change, LOCAL_CHANGE_ADDRESS);
  TxOut remote_change_output = TxOut(remote_change, REMOTE_CHANGE_ADDRESS);

  // Act
  auto fund_tx = DlcManager::CreateFundTransaction(
    LOCAL_FUND_PUBKEY, REMOTE_FUND_PUBKEY, FUND_OUTPUT, LOCAL_INPUTS_INFO,
    local_change_output, REMOTE_INPUTS_INFO, remote_change_output, PREMIUM_DEST,
    OPTION_PREMIUM);

  EXPECT_EQ(FUND_TX_WITH_PREMIUM_HEX.GetHex(), fund_tx.GetHex());
  EXPECT_EQ(FUND_OUTPUT, fund_tx.GetTransaction().GetTxOut(0).GetValue());
  EXPECT_EQ(local_change, fund_tx.GetTransaction().GetTxOut(1).GetValue());
  EXPECT_EQ(remote_change, fund_tx.GetTransaction().GetTxOut(2).GetValue());
  EXPECT_EQ(
    OPTION_PREMIUM,
    fund_tx.GetTransaction().GetTxOut(3).GetValue().GetSatoshiValue());
}

TEST(DlcManager, CreateDlcTransactionsWithPremium) {
  // Arrange
  std::vector<DlcOutcome> outcomes = {
    {WIN_AMOUNT, LOSE_AMOUNT}, {LOSE_AMOUNT, WIN_AMOUNT}};

  // Act
  auto dlc_transactions = DlcManager::CreateDlcTransactions(
    outcomes, LOCAL_PARAMS, REMOTE_PARAMS, REFUND_LOCKTIME, 1, PREMIUM_DEST,
    OPTION_PREMIUM);
  auto fund_tx = dlc_transactions.fund_transaction;

  // Assert
  EXPECT_EQ(FUND_TX_WITH_PREMIUM_HEX.GetHex(), fund_tx.GetHex());
  EXPECT_EQ(4, fund_tx.GetTransaction().GetTxOutCount());
  EXPECT_GT(
    (LOCAL_INPUT_AMOUNT - LOCAL_COLLATERAL_AMOUNT - OPTION_PREMIUM)
      .GetSatoshiValue(),
    fund_tx.GetTransaction().GetTxOut(1).GetValue().GetSatoshiValue());
  EXPECT_EQ(
    OPTION_PREMIUM.GetSatoshiValue(),
    fund_tx.GetTransaction().GetTxOut(3).GetValue().GetSatoshiValue());
}

TEST(DlcManager, CreateDlcTransactionsWithPremiumEmptyDestAddressFails) {
  // Arrange
  std::vector<DlcOutcome> outcomes = {
    {WIN_AMOUNT, LOSE_AMOUNT}, {LOSE_AMOUNT, WIN_AMOUNT}};

  // Act/Assert
  EXPECT_THROW(
    DlcManager::CreateDlcTransactions(
      outcomes, LOCAL_PARAMS, REMOTE_PARAMS, REFUND_LOCKTIME, 1, Address(),
      OPTION_PREMIUM),
    CfdException);
}

TEST(DlcManager, AdaptorSigTest) {
  std::vector<DlcOutcome> payouts = {
    {WIN_AMOUNT, LOSE_AMOUNT}, {LOSE_AMOUNT, WIN_AMOUNT}};
  auto dlc_transactions = DlcManager::CreateDlcTransactions(
    payouts, LOCAL_PARAMS, REMOTE_PARAMS, REFUND_LOCKTIME, 1, PREMIUM_DEST,
    OPTION_PREMIUM);
  auto fund_transaction = dlc_transactions.fund_transaction;
  auto cets = dlc_transactions.cets;
  auto cet0 = cets[0];
  auto lock_script = DlcManager::CreateFundTxLockingScript(
    LOCAL_FUND_PUBKEY, REMOTE_FUND_PUBKEY);

  auto fund_amount = fund_transaction.GetTransaction().GetTxOut(0).GetValue();
  auto fund_txid = fund_transaction.GetTransaction().GetTxid();

  auto adaptor_pairs = DlcManager::CreateCetAdaptorSignatures(
    cets, ORACLE_PUBKEY, {ORACLE_R_POINTS[0]}, LOCAL_FUND_PRIVKEY, lock_script,
    fund_amount, {{WIN_MESSAGES_HASH[0]}, {LOSE_MESSAGES_HASH[0]}});

  EXPECT_TRUE(DlcManager::VerifyCetAdaptorSignature(
    adaptor_pairs[1], cets[1], LOCAL_FUND_PUBKEY, ORACLE_PUBKEY,
    {ORACLE_R_POINTS[0]}, lock_script, fund_amount, {LOSE_MESSAGES_HASH[0]}));

  auto adapted_sig = AdaptorUtil::Adapt(
    adaptor_pairs[0].signature, ORACLE_SIGNATURES[0].GetPrivkey());

  auto is_valid = cet0.VerifyInputSignature(
    adapted_sig, LOCAL_FUND_PUBKEY, fund_txid, 0, lock_script, SigHashType(),
    fund_amount, WitnessVersion::kVersion0);
  EXPECT_TRUE(is_valid);
}

TEST(DlcManager, AdaptorSigMultipleNonces) {
  std::vector<DlcOutcome> outcomes = {
    {WIN_AMOUNT, LOSE_AMOUNT}, {LOSE_AMOUNT, WIN_AMOUNT}};
  auto dlc_transactions = DlcManager::CreateDlcTransactions(
    outcomes, LOCAL_PARAMS, REMOTE_PARAMS, REFUND_LOCKTIME, 1, PREMIUM_DEST,
    OPTION_PREMIUM);
  auto fund_transaction = dlc_transactions.fund_transaction;
  auto cets = dlc_transactions.cets;
  auto cet0 = cets[0];
  auto lock_script = DlcManager::CreateFundTxLockingScript(
    LOCAL_FUND_PUBKEY, REMOTE_FUND_PUBKEY);

  auto fund_amount = fund_transaction.GetTransaction().GetTxOut(0).GetValue();
  auto fund_txid = fund_transaction.GetTransaction().GetTxid();

  auto adaptor_pairs = DlcManager::CreateCetAdaptorSignatures(
    cets, ORACLE_PUBKEY, ORACLE_R_POINTS, LOCAL_FUND_PRIVKEY, lock_script,
    fund_amount, {WIN_MESSAGES_HASH, LOSE_MESSAGES_HASH});

  EXPECT_TRUE(DlcManager::VerifyCetAdaptorSignature(
    adaptor_pairs[1], cets[1], LOCAL_FUND_PUBKEY, ORACLE_PUBKEY,
    ORACLE_R_POINTS, lock_script, fund_amount, LOSE_MESSAGES_HASH));

  auto adaptor_secret = ORACLE_SIGNATURES[0].GetPrivkey();
  adaptor_secret = adaptor_secret.CreateTweakAdd(
    ByteData256(ORACLE_SIGNATURES[1].GetPrivkey().GetData()));
  auto adapted_sig =
    AdaptorUtil::Adapt(adaptor_pairs[0].signature, adaptor_secret);

  auto is_valid = cet0.VerifyInputSignature(
    adapted_sig, LOCAL_FUND_PUBKEY, fund_txid, 0, lock_script, SigHashType(),
    fund_amount, WitnessVersion::kVersion0);
  EXPECT_TRUE(is_valid);
}

TEST(DlcManager, AdaptorSigMultipleNoncesWithFewerMessagesThanNonces) {
  std::vector<DlcOutcome> outcomes = {
    {WIN_AMOUNT, LOSE_AMOUNT}, {LOSE_AMOUNT, WIN_AMOUNT}};
  auto dlc_transactions = DlcManager::CreateDlcTransactions(
    outcomes, LOCAL_PARAMS, REMOTE_PARAMS, REFUND_LOCKTIME, 1, PREMIUM_DEST,
    OPTION_PREMIUM);
  auto fund_transaction = dlc_transactions.fund_transaction;
  auto cets = dlc_transactions.cets;
  auto cet0 = cets[0];
  auto lock_script = DlcManager::CreateFundTxLockingScript(
    LOCAL_FUND_PUBKEY, REMOTE_FUND_PUBKEY);

  auto fund_amount = fund_transaction.GetTransaction().GetTxOut(0).GetValue();
  auto fund_txid = fund_transaction.GetTransaction().GetTxid();

  auto adaptor_pairs = DlcManager::CreateCetAdaptorSignatures(
    cets, ORACLE_PUBKEY, ORACLE_R_POINTS, LOCAL_FUND_PRIVKEY, lock_script,
    fund_amount,
    {WIN_MESSAGES_HASH_FEWER_MESSAGES, LOSE_MESSAGES_HASH_FEWER_MESSAGES});

  EXPECT_TRUE(DlcManager::VerifyCetAdaptorSignature(
    adaptor_pairs[1], cets[1], LOCAL_FUND_PUBKEY, ORACLE_PUBKEY,
    {ORACLE_R_POINTS[0]}, lock_script, fund_amount,
    LOSE_MESSAGES_HASH_FEWER_MESSAGES));

  auto adaptor_secret = ORACLE_SIGNATURES[0].GetPrivkey();
  auto adapted_sig =
    AdaptorUtil::Adapt(adaptor_pairs[0].signature, adaptor_secret);

  auto is_valid = cet0.VerifyInputSignature(
    adapted_sig, LOCAL_FUND_PUBKEY, fund_txid, 0, lock_script, SigHashType(),
    fund_amount, WitnessVersion::kVersion0);
  EXPECT_TRUE(is_valid);
}

TEST(DlcManager, AdaptorSigMultipleNoncesWithMoreMessagesThanNoncesFails) {
  std::vector<DlcOutcome> outcomes = {
    {WIN_AMOUNT, LOSE_AMOUNT}, {LOSE_AMOUNT, WIN_AMOUNT}};
  auto dlc_transactions = DlcManager::CreateDlcTransactions(
    outcomes, LOCAL_PARAMS, REMOTE_PARAMS, REFUND_LOCKTIME, 1, PREMIUM_DEST,
    OPTION_PREMIUM);
  auto fund_transaction = dlc_transactions.fund_transaction;
  auto cets = dlc_transactions.cets;
  auto cet0 = cets[0];
  auto lock_script = DlcManager::CreateFundTxLockingScript(
    LOCAL_FUND_PUBKEY, REMOTE_FUND_PUBKEY);

  auto fund_amount = fund_transaction.GetTransaction().GetTxOut(0).GetValue();
  auto fund_txid = fund_transaction.GetTransaction().GetTxid();

  // Act/Assert
  EXPECT_THROW(
    DlcManager::CreateCetAdaptorSignatures(
      cets, ORACLE_PUBKEY, ORACLE_R_POINTS, LOCAL_FUND_PRIVKEY, lock_script,
      fund_amount,
      {WIN_MESSAGES_HASH, LOSE_MESSAGES_HASH, WIN_MESSAGES_HASH_FEWER_MESSAGES,
       LOSE_MESSAGES_HASH_FEWER_MESSAGES}),
    CfdException);
}

TEST(DlcManager, CreateDlcTransactionsWithUniqueSerialId) {
  // Arrange
  std::vector<DlcOutcome> outcomes = {
    {WIN_AMOUNT, LOSE_AMOUNT}, {LOSE_AMOUNT, WIN_AMOUNT}};

  // Act
  auto dlc_transactions = DlcManager::CreateDlcTransactions(
    outcomes, LOCAL_PARAMS_SERIAL_ID, REMOTE_PARAMS_SERIAL_ID, REFUND_LOCKTIME,
    1, PREMIUM_DEST, Amount::CreateBySatoshiAmount(0), 0, 0, 8702);
  auto fund_tx = dlc_transactions.fund_transaction;
  DlcManager::SignFundTransactionInput(
    &fund_tx, LOCAL_INPUT_PRIVKEY, LOCAL_INPUTS[0].GetTxid(), 0,
    LOCAL_INPUT_AMOUNT);
  DlcManager::SignFundTransactionInput(
    &fund_tx, REMOTE_INPUT_PRIVKEY, REMOTE_INPUTS[0].GetTxid(), 0,
    REMOTE_INPUT_AMOUNT);

  auto local_fund_signature =
    DlcManager::GetRawFundingTransactionInputSignature(
      fund_tx, LOCAL_INPUT_PRIVKEY, LOCAL_INPUTS[0].GetTxid(), 0,
      LOCAL_INPUT_AMOUNT);

  bool is_local_fund_signature_valid = DlcManager::VerifyFundTxSignature(
    fund_tx, local_fund_signature, LOCAL_INPUT_PUBKEY,
    LOCAL_INPUTS[0].GetTxid(), 0, LOCAL_INPUT_AMOUNT);

  auto remote_fund_signature =
    DlcManager::GetRawFundingTransactionInputSignature(
      fund_tx, REMOTE_INPUT_PRIVKEY, REMOTE_INPUTS[0].GetTxid(), 0,
      REMOTE_INPUT_AMOUNT);

  bool is_remote_fund_signature_valid = DlcManager::VerifyFundTxSignature(
    fund_tx, remote_fund_signature, REMOTE_INPUT_PUBKEY,
    REMOTE_INPUTS[0].GetTxid(), 0, REMOTE_INPUT_AMOUNT);

  auto refund_tx = dlc_transactions.refund_transaction;

  auto fund_tx_id = fund_tx.GetTransaction().GetTxid();

  auto local_refund_signature = DlcManager::GetRawRefundTxSignature(
    refund_tx, LOCAL_FUND_PRIVKEY, LOCAL_FUND_PUBKEY, REMOTE_FUND_PUBKEY,
    FUND_OUTPUT, fund_tx_id, 2);

  auto remote_refund_signature = DlcManager::GetRawRefundTxSignature(
    refund_tx, REMOTE_FUND_PRIVKEY, LOCAL_FUND_PUBKEY, REMOTE_FUND_PUBKEY,
    FUND_OUTPUT, fund_tx_id, 2);

  DlcManager::AddSignaturesToRefundTx(
    &refund_tx, LOCAL_FUND_PUBKEY, REMOTE_FUND_PUBKEY,
    {local_refund_signature, remote_refund_signature}, fund_tx_id, 2);

  bool is_local_refund_signature_valid = DlcManager::VerifyRefundTxSignature(
    refund_tx, local_refund_signature, LOCAL_FUND_PUBKEY, REMOTE_FUND_PUBKEY,
    FUND_OUTPUT, false, fund_tx_id, 2);

  bool is_remote_refund_signature_valid = DlcManager::VerifyRefundTxSignature(
    refund_tx, remote_refund_signature, LOCAL_FUND_PUBKEY, REMOTE_FUND_PUBKEY,
    FUND_OUTPUT, true, fund_tx_id, 2);

  auto cets = dlc_transactions.cets;
  auto nb_cet = cets.size();

  auto fund_script = DlcManager::CreateFundTxLockingScript(
    LOCAL_FUND_PUBKEY, REMOTE_FUND_PUBKEY);

  bool all_valid_cet_signatures = true;
  for (size_t i = 0; i < nb_cet; i++) {
    auto local_cet_adaptor_pair = DlcManager::CreateCetAdaptorSignature(
      cets[i], ORACLE_PUBKEY, {ORACLE_R_POINTS[0]}, LOCAL_FUND_PRIVKEY,
      fund_script, FUND_OUTPUT, {MESSAGES_HASH[i][0]});
    all_valid_cet_signatures &= DlcManager::VerifyCetAdaptorSignature(
      local_cet_adaptor_pair, cets[i], LOCAL_FUND_PUBKEY, ORACLE_PUBKEY,
      {ORACLE_R_POINTS[0]}, fund_script, FUND_OUTPUT, {MESSAGES_HASH[i][0]});
    auto remote_cet_adaptor_pair = DlcManager::CreateCetAdaptorSignature(
      cets[i], ORACLE_PUBKEY, {ORACLE_R_POINTS[0]}, LOCAL_FUND_PRIVKEY,
      fund_script, FUND_OUTPUT, {MESSAGES_HASH[i][0]});
    all_valid_cet_signatures &= DlcManager::VerifyCetAdaptorSignature(
      remote_cet_adaptor_pair, cets[i], LOCAL_FUND_PUBKEY, ORACLE_PUBKEY,
      {ORACLE_R_POINTS[0]}, fund_script, FUND_OUTPUT, {MESSAGES_HASH[i][0]});
  }

  auto local_cet_adaptor_pairs = DlcManager::CreateCetAdaptorSignatures(
    cets, ORACLE_PUBKEY, {ORACLE_R_POINTS[0]}, LOCAL_FUND_PRIVKEY, fund_script,
    FUND_OUTPUT, {{WIN_MESSAGES_HASH[0]}, {LOSE_MESSAGES_HASH[0]}});

  bool all_valid_cet_pair_batch = DlcManager::VerifyCetAdaptorSignatures(
    cets, local_cet_adaptor_pairs,
    {{WIN_MESSAGES_HASH[0]}, {LOSE_MESSAGES_HASH[0]}}, LOCAL_FUND_PUBKEY,
    ORACLE_PUBKEY, {ORACLE_R_POINTS[0]}, fund_script, FUND_OUTPUT);
  auto remote_cet_adaptor_pairs = DlcManager::CreateCetAdaptorSignatures(
    cets, ORACLE_PUBKEY, {ORACLE_R_POINTS[0]}, LOCAL_FUND_PRIVKEY, fund_script,
    FUND_OUTPUT, {{WIN_MESSAGES_HASH[0]}, {LOSE_MESSAGES_HASH[0]}});

  all_valid_cet_pair_batch &= DlcManager::VerifyCetAdaptorSignatures(
    cets, remote_cet_adaptor_pairs,
    {{WIN_MESSAGES_HASH[0]}, {LOSE_MESSAGES_HASH[0]}}, LOCAL_FUND_PUBKEY,
    ORACLE_PUBKEY, {ORACLE_R_POINTS[0]}, fund_script, FUND_OUTPUT);

  EXPECT_EQ(dlc_transactions.cets.size(), outcomes.size());
  EXPECT_EQ(FUND_TX_WITH_SERIAL_ID_INPUTS_HEX.GetHex(), fund_tx.GetHex());
  EXPECT_TRUE(is_local_fund_signature_valid);
  EXPECT_TRUE(is_remote_fund_signature_valid);
  EXPECT_EQ(REFUND_INPUTS_SERIAL_ID_HEX.GetHex(), refund_tx.GetHex());
  EXPECT_TRUE(is_local_refund_signature_valid);
  EXPECT_TRUE(is_remote_refund_signature_valid);
  EXPECT_TRUE(all_valid_cet_signatures);
  EXPECT_TRUE(all_valid_cet_pair_batch);
}

TEST(DlcManager, CetTestSerialId) {
  // Arrange
  auto local_payout = Amount::CreateBySatoshiAmount(199900000);
  auto remote_payout = Amount::CreateBySatoshiAmount(100000);
  TxOut local_output(local_payout, LOCAL_FINAL_ADDRESS);
  TxOut remote_output(remote_payout, REMOTE_FINAL_ADDRESS);
  // Act
  auto cet = DlcManager::CreateCet(
    local_output, remote_output, FUND_TX_SERIAL_ID, 0, 0, 3048, 2032);

  auto fund_script = DlcManager::CreateFundTxLockingScript(
    LOCAL_FUND_PUBKEY, REMOTE_FUND_PUBKEY);
  auto local_adaptor_pair = DlcManager::CreateCetAdaptorSignature(
    cet, ORACLE_PUBKEY, {ORACLE_R_POINTS[0]}, LOCAL_FUND_PRIVKEY, fund_script,
    FUND_OUTPUT, {WIN_MESSAGES_HASH[0]});
  auto remote_adaptor_pair = DlcManager::CreateCetAdaptorSignature(
    cet, ORACLE_PUBKEY, {ORACLE_R_POINTS[0]}, REMOTE_FUND_PRIVKEY, fund_script,
    FUND_OUTPUT, {WIN_MESSAGES_HASH[0]});

  // Assert
  EXPECT_EQ(
    FUND_TX_SERIAL_ID.GetHex(),
    cet.GetTransaction().GetTxIn(0).GetTxid().GetHex());
  EXPECT_EQ(0, cet.GetTransaction().GetTxIn(0).GetVout());
  EXPECT_EQ(remote_payout, cet.GetTransaction().GetTxOut(0).GetValue());
  EXPECT_TRUE(
    cet.GetTransaction().GetTxOut(0).GetLockingScript().IsP2wpkhScript());
  EXPECT_EQ(local_payout, cet.GetTransaction().GetTxOut(1).GetValue());
  EXPECT_TRUE(
    cet.GetTransaction().GetTxOut(1).GetLockingScript().IsP2wpkhScript());
  EXPECT_EQ(CET_SERIAL_ID_HEX.GetHex(), cet.GetHex());
  EXPECT_TRUE(DlcManager::VerifyCetAdaptorSignature(
    local_adaptor_pair, cet, LOCAL_FUND_PUBKEY, ORACLE_PUBKEY,
    {ORACLE_R_POINTS[0]}, fund_script, FUND_OUTPUT, {WIN_MESSAGES_HASH[0]}));
  EXPECT_TRUE(DlcManager::VerifyCetAdaptorSignature(
    remote_adaptor_pair, cet, REMOTE_FUND_PUBKEY, ORACLE_PUBKEY,
    {ORACLE_R_POINTS[0]}, fund_script, FUND_OUTPUT, {WIN_MESSAGES_HASH[0]}));

  DlcManager::SignCet(
    &cet, local_adaptor_pair.signature, {ORACLE_SIGNATURES[0]},
    REMOTE_FUND_PRIVKEY, fund_script, FUND_TX_SERIAL_ID, 0, FUND_OUTPUT);
  EXPECT_EQ(cet.GetHex(), CET_SERIAL_ID_HEX_SIGNED.GetHex());
}
