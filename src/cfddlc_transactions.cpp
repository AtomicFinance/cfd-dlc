// Copyright 2019 CryptoGarage

#include "cfddlc/cfddlc_transactions.h"

#include <algorithm>
#include <cmath>
#include <cstring>
#include <iostream>
#include <numeric>
#include <string>
#include <tuple>
#include <vector>

#include "cfd/cfd_transaction.h"
#include "cfdcore/cfdcore_address.h"
#include "cfdcore/cfdcore_amount.h"
#include "cfdcore/cfdcore_common.h"
#include "cfdcore/cfdcore_exception.h"
#include "cfdcore/cfdcore_hdwallet.h"
#include "cfdcore/cfdcore_schnorrsig.h"
#include "cfdcore/cfdcore_script.h"
#include "cfdcore/cfdcore_transaction.h"
#include "cfdcore/cfdcore_util.h"
#include "secp256k1.h"  // NOLINT

namespace cfd {
namespace dlc {

using cfd::Amount;
using cfd::Script;
using cfd::TransactionController;
using cfd::core::AdaptorUtil;
using cfd::core::Address;
using cfd::core::AddressType;
using cfd::core::ByteData;
using cfd::core::ByteData256;
using cfd::core::CfdError;
using cfd::core::CfdException;
using cfd::core::CryptoUtil;
using cfd::core::ExtPrivkey;
using cfd::core::ExtPubkey;
using cfd::core::HashUtil;
using cfd::core::NetType;
using cfd::core::Privkey;
using cfd::core::Pubkey;
using cfd::core::SchnorrUtil;
using cfd::core::ScriptBuilder;
using cfd::core::ScriptOperator;
using cfd::core::ScriptUtil;
using cfd::core::SigHashAlgorithm;
using cfd::core::SigHashType;
using cfd::core::SignatureUtil;
using cfd::core::Txid;
using cfd::core::TxIn;
using cfd::core::TxOut;
using cfd::core::WitnessVersion;

static const uint32_t TX_VERSION = 2;

static const uint64_t DUST_LIMIT = 1000;

const uint32_t FUND_TX_BASE_WEIGHT = 214;
const uint32_t BATCH_FUND_TX_BASE_WEIGHT = 42;
const uint32_t FUNDING_OUTPUT_SIZE = 43;
const uint32_t CET_BASE_WEIGHT = 498;

static bool CompareSerialId(TxInputInfo i1, TxInputInfo i2) {
  return (i1.input_serial_id < i2.input_serial_id);
}

static bool CompareOutputSerialId(TxOutputInfo i1, TxOutputInfo i2) {
  return (i1.output_serial_id < i2.output_serial_id);
}

TransactionController DlcManager::CreateCet(
  const TxOut &local_output,
  const TxOut &remote_output,
  const Txid &fund_tx_id,
  const uint32_t fund_vout,
  uint32_t lock_time,
  uint64_t local_serial_id,
  uint64_t remote_serial_id) {
  auto cet_tx = TransactionController(TX_VERSION, lock_time);

  std::vector<TxOutputInfo> outputs_info;

  TxOutputInfo local_output_info = {
    local_output.GetLockingScript(), local_output.GetValue(), local_serial_id};
  TxOutputInfo remote_output_info = {
    remote_output.GetLockingScript(), remote_output.GetValue(),
    remote_serial_id};

  outputs_info.push_back(local_output_info);
  outputs_info.push_back(remote_output_info);

  std::sort(outputs_info.begin(), outputs_info.end(), CompareOutputSerialId);

  for (size_t i = 0; i < outputs_info.size(); i++) {
    if (!IsDustOutputInfo(outputs_info[i])) {
      cet_tx.AddTxOut(outputs_info[i].script, outputs_info[i].value);
    }
  }

  cet_tx.AddTxIn(fund_tx_id, fund_vout);
  return cet_tx;
}

std::vector<TransactionController> DlcManager::CreateCets(
  const Txid &fund_tx_id,
  const uint32_t fund_vout,
  const Script &local_final_script_pubkey,
  const Script &remote_final_script_pubkey,
  const std::vector<DlcOutcome> outcomes,
  uint32_t lock_time,
  uint64_t local_serial_id,
  uint64_t remote_serial_id) {
  std::vector<TransactionController> cets;
  cets.reserve(outcomes.size());

  for (auto outcome : outcomes) {
    TxOut local_output(outcome.local_payout, local_final_script_pubkey);
    TxOut remote_output(outcome.remote_payout, remote_final_script_pubkey);
    cets.push_back(CreateCet(
      local_output, remote_output, fund_tx_id, fund_vout, lock_time,
      local_serial_id, remote_serial_id));
  }

  return cets;
}

static std::vector<Pubkey> GetOrderedPubkeys(const Pubkey &a, const Pubkey &b) {
  return a.GetHex() < b.GetHex() ? std::vector<Pubkey>{a, b}
                                 : std::vector<Pubkey>{b, a};
}

Script DlcManager::CreateFundTxLockingScript(
  const Pubkey &local_fund_pubkey, const Pubkey &remote_fund_pubkey) {
  auto pubkeys = GetOrderedPubkeys(local_fund_pubkey, remote_fund_pubkey);
  return ScriptUtil::CreateMultisigRedeemScript(2, pubkeys);
}

// refers to public instance
TransactionController DlcManager::CreateFundTransaction(
  const Pubkey &local_fund_pubkey,
  const Pubkey &remote_fund_pubkey,
  const Amount &output_amount,
  const std::vector<TxInputInfo> &local_inputs_info,
  const TxOut &local_change_output,
  const std::vector<TxInputInfo> &remote_inputs_info,
  const TxOut &remote_change_output,
  const Address &option_dest,
  const Amount &option_premium,
  const uint64_t lock_time,
  const uint64_t local_serial_id,
  const uint64_t remote_serial_id,
  const uint64_t output_serial_id) {
  auto transaction = TransactionController(TX_VERSION, lock_time);
  auto multi_sig_script =
    CreateFundTxLockingScript(local_fund_pubkey, remote_fund_pubkey);
  auto wit_script = ScriptUtil::CreateP2wshLockingScript(multi_sig_script);

  std::vector<TxOutputInfo> outputs_info;

  TxOutputInfo fund_output_info = {wit_script, output_amount, output_serial_id};

  TxOutputInfo local_output_info = {
    local_change_output.GetLockingScript(), local_change_output.GetValue(),
    local_serial_id};
  TxOutputInfo remote_output_info = {
    remote_change_output.GetLockingScript(), remote_change_output.GetValue(),
    remote_serial_id};

  outputs_info.push_back(fund_output_info);
  outputs_info.push_back(local_output_info);
  outputs_info.push_back(remote_output_info);

  std::sort(outputs_info.begin(), outputs_info.end(), CompareOutputSerialId);

  for (size_t i = 0; i < outputs_info.size(); i++) {
    transaction.AddTxOut(outputs_info[i].script, outputs_info[i].value);
  }

  std::vector<TxInputInfo> inputs_info;
  inputs_info.reserve(local_inputs_info.size() + remote_inputs_info.size());
  inputs_info.insert(
    inputs_info.end(), local_inputs_info.begin(), local_inputs_info.end());
  inputs_info.insert(
    inputs_info.end(), remote_inputs_info.begin(), remote_inputs_info.end());

  std::sort(inputs_info.begin(), inputs_info.end(), CompareSerialId);

  std::vector<TxIn> inputs;

  for (size_t i = 0; i < inputs_info.size(); i++) {
    inputs.push_back(inputs_info[i].input);
  }

  for (auto it = inputs.cbegin(); it != inputs.end(); ++it) {
    transaction.AddTxIn(it->GetTxid(), it->GetVout(), it->GetUnlockingScript());
  }

  if (option_premium > 0) {
    TxOut option_out(option_premium, option_dest);
    if (!IsDustOutput(option_out)) {
      transaction.AddTxOut(
        option_out.GetLockingScript(), option_out.GetValue());
    }
  }

  return transaction;
}

TransactionController DlcManager::CreateBatchFundTransaction(
  const std::vector<Pubkey> &local_fund_pubkeys,
  const std::vector<Pubkey> &remote_fund_pubkeys,
  const std::vector<Amount> &output_amounts,
  const std::vector<TxInputInfo> &local_inputs_info,
  const TxOut &local_change_output,
  const std::vector<TxInputInfo> &remote_inputs_info,
  const TxOut &remote_change_output,
  const uint64_t lock_time,
  const uint64_t local_serial_id,
  const uint64_t remote_serial_id,
  const std::vector<uint64_t> &output_serial_ids) {
  if (
    local_fund_pubkeys.size() != remote_fund_pubkeys.size() ||
    local_fund_pubkeys.size() != output_amounts.size()) {
    throw CfdException(
      CfdError::kCfdIllegalArgumentError,
      "Number of local pubkeys, remote pubkeys, and output "
      "amounts must be equal.");
  }

  auto transaction = TransactionController(TX_VERSION, lock_time);

  std::vector<TxOutputInfo> outputs_info;

  for (size_t i = 0; i < local_fund_pubkeys.size(); i++) {
    auto multi_sig_script =
      CreateFundTxLockingScript(local_fund_pubkeys[i], remote_fund_pubkeys[i]);
    auto wit_script = ScriptUtil::CreateP2wshLockingScript(multi_sig_script);

    uint64_t serial_id = output_serial_ids.empty() ? 0 : output_serial_ids[i];

    TxOutputInfo fund_output_info = {
      wit_script,
      output_amounts[i],
      serial_id,
    };

    outputs_info.push_back(fund_output_info);
  }

  TxOutputInfo local_output_info = {
    local_change_output.GetLockingScript(), local_change_output.GetValue(),
    local_serial_id};
  TxOutputInfo remote_output_info = {
    remote_change_output.GetLockingScript(), remote_change_output.GetValue(),
    remote_serial_id};

  outputs_info.push_back(local_output_info);
  outputs_info.push_back(remote_output_info);

  std::sort(outputs_info.begin(), outputs_info.end(), CompareOutputSerialId);

  for (const auto &output_info : outputs_info) {
    transaction.AddTxOut(output_info.script, output_info.value);
  }

  std::vector<TxInputInfo> inputs_info;
  inputs_info.reserve(local_inputs_info.size() + remote_inputs_info.size());
  inputs_info.insert(
    inputs_info.end(), local_inputs_info.begin(), local_inputs_info.end());
  inputs_info.insert(
    inputs_info.end(), remote_inputs_info.begin(), remote_inputs_info.end());

  std::sort(inputs_info.begin(), inputs_info.end(), CompareSerialId);

  for (const auto &input_info : inputs_info) {
    transaction.AddTxIn(
      input_info.input.GetTxid(), input_info.input.GetVout(),
      input_info.input.GetUnlockingScript());
  }

  return transaction;
}

TransactionController DlcManager::CreateRefundTransaction(
  const Script &local_final_script_pubkey,
  const Script &remote_final_script_pubkey,
  const Amount &local_amount,
  const Amount &remote_amount,
  uint32_t lock_time,
  const Txid &fund_tx_id,
  uint32_t fund_vout) {
  auto transaction_controller = TransactionController(TX_VERSION, lock_time);
  transaction_controller.AddTxIn(fund_tx_id, fund_vout);
  transaction_controller.AddTxOut(local_final_script_pubkey, local_amount);
  transaction_controller.AddTxOut(remote_final_script_pubkey, remote_amount);
  return transaction_controller;
}

void DlcManager::SignFundTransactionInput(
  TransactionController *fund_transaction,
  const Privkey &privkey,
  const Txid &prev_tx_id,
  uint32_t prev_tx_vout,
  const Amount &value) {
  auto raw_signature = GetRawFundingTransactionInputSignature(
    *fund_transaction, privkey, prev_tx_id, prev_tx_vout, value);
  auto hash_type = SigHashType(SigHashAlgorithm::kSigHashAll);
  auto signature = CryptoUtil::ConvertSignatureToDer(raw_signature, hash_type);
  fund_transaction->AddWitnessStack(
    prev_tx_id, prev_tx_vout, signature.GetHex(), privkey.GeneratePubkey());
}

void DlcManager::AddSignatureToFundTransaction(
  TransactionController *fund_transaction,
  const ByteData &signature,
  const Pubkey &pubkey,
  const Txid &prev_tx_id,
  uint32_t prev_tx_vout) {
  auto der_signature =
    CryptoUtil::ConvertSignatureToDer(signature, SigHashType());
  fund_transaction->AddWitnessStack(
    prev_tx_id, prev_tx_vout, der_signature.GetHex(), pubkey);
}

bool DlcManager::VerifyFundTxSignature(
  const TransactionController &fund_tx,
  const ByteData &signature,
  const Pubkey &pubkey,
  const Txid &txid,
  uint32_t vout,
  const Amount &input_amount) {
  return fund_tx.VerifyInputSignature(
    signature, pubkey, txid, vout, SigHashType(SigHashAlgorithm::kSigHashAll),
    input_amount, WitnessVersion::kVersion0);
}

AdaptorPair DlcManager::CreateCetAdaptorSignature(
  const TransactionController &cet,
  const SchnorrPubkey &oracle_pubkey,
  const std::vector<SchnorrPubkey> &oracle_r_values,
  const Privkey &funding_sk,
  const Script &funding_script_pubkey,
  const Amount &total_collateral,
  const std::vector<ByteData256> &msgs) {
  auto adaptor_point =
    ComputeAdaptorPoint(msgs, oracle_r_values, oracle_pubkey);

  auto sig_hash = cet.GetTransaction().GetSignatureHash(
    0, funding_script_pubkey.GetData(), SigHashType(), total_collateral,
    WitnessVersion::kVersion0);
  return AdaptorUtil::Sign(sig_hash, funding_sk, adaptor_point);
}

std::vector<AdaptorPair> DlcManager::CreateCetAdaptorSignatures(
  const std::vector<TransactionController> &cets,
  const SchnorrPubkey &oracle_pubkey,
  const std::vector<SchnorrPubkey> &oracle_r_values,
  const Privkey &funding_sk,
  const Script &funding_script_pubkey,
  const Amount &total_collateral,
  const std::vector<std::vector<ByteData256>> &msgs) {
  size_t nb = cets.size();
  if (nb != msgs.size()) {
    throw CfdException(
      CfdError::kCfdIllegalArgumentError,
      "Number of cets differ from number of messages");
  }

  std::vector<AdaptorPair> sigs;
  for (size_t i = 0; i < nb; i++) {
    if (oracle_r_values.size() < msgs[i].size()) {
      throw CfdException(
        CfdError::kCfdIllegalArgumentError,
        "Number of r values must be greater or equal to number of messages.");
    }
    std::vector<SchnorrPubkey> r_values;
    for (size_t j = 0; j < msgs[i].size(); j++) {
      r_values.push_back(oracle_r_values[j]);
    }
    sigs.push_back(CreateCetAdaptorSignature(
      cets[i], oracle_pubkey, r_values, funding_sk, funding_script_pubkey,
      total_collateral, msgs[i]));
  }

  return sigs;
}

bool DlcManager::VerifyCetAdaptorSignature(
  const AdaptorPair &adaptor_pair,
  const TransactionController &cet,
  const Pubkey &pubkey,
  const SchnorrPubkey &oracle_pubkey,
  const std::vector<SchnorrPubkey> &oracle_r_values,
  const Script &funding_script_pubkey,
  const Amount &total_collateral,
  const std::vector<ByteData256> &msgs) {
  auto adaptor_point =
    ComputeAdaptorPoint(msgs, oracle_r_values, oracle_pubkey);
  auto sig_hash = cet.GetTransaction().GetSignatureHash(
    0, funding_script_pubkey.GetData(), SigHashType(), total_collateral,
    WitnessVersion::kVersion0);
  return AdaptorUtil::Verify(
    adaptor_pair.signature, adaptor_pair.proof, adaptor_point, sig_hash,
    pubkey);
}

bool DlcManager::VerifyCetAdaptorSignatures(
  const std::vector<TransactionController> &cets,
  const std::vector<AdaptorPair> &signature_and_proofs,
  const std::vector<std::vector<ByteData256>> &msgs,
  const Pubkey &pubkey,
  const SchnorrPubkey &oracle_pubkey,
  const std::vector<SchnorrPubkey> &oracle_r_values,
  const Script &funding_script_pubkey,
  const Amount &total_collateral) {
  auto nb = cets.size();
  if (nb != signature_and_proofs.size() || nb != msgs.size()) {
    throw CfdException(
      CfdError::kCfdIllegalArgumentError,
      "Number of transactions, signatures and messages differs.");
  }

  bool all_valid = true;

  for (size_t i = 0; i < nb && all_valid; i++) {
    if (oracle_r_values.size() < msgs[i].size()) {
      throw CfdException(
        CfdError::kCfdIllegalArgumentError,
        "Number of r values must be greater or equal to number of messages.");
    }
    std::vector<SchnorrPubkey> r_values;
    for (size_t j = 0; j < msgs[i].size(); j++) {
      r_values.push_back(oracle_r_values[j]);
    }
    all_valid &= VerifyCetAdaptorSignature(
      signature_and_proofs[i], cets[i], pubkey, oracle_pubkey, r_values,
      funding_script_pubkey, total_collateral, msgs[i]);
  }

  return all_valid;
}

void DlcManager::SignCet(
  TransactionController *cet,
  const AdaptorSignature &adaptor_sig,
  const std::vector<SchnorrSignature> &oracle_signatures,
  const Privkey funding_sk,
  const Script &funding_script_pubkey,
  const Txid &fund_tx_id,
  uint32_t fund_vout,
  const Amount &fund_amount) {
  if (oracle_signatures.size() < 1) {
    throw CfdException(
      CfdError::kCfdIllegalArgumentError, "No oracle signature provided.");
  }

  auto adaptor_secret = oracle_signatures[0].GetPrivkey();

  for (size_t i = 1; i < oracle_signatures.size(); i++) {
    adaptor_secret = adaptor_secret.CreateTweakAdd(
      ByteData256(oracle_signatures[i].GetPrivkey().GetData()));
  }

  auto adapted_sig = AdaptorUtil::Adapt(adaptor_sig, adaptor_secret);
  auto sig_hash = cet->GetTransaction().GetSignatureHash(
    0, funding_script_pubkey.GetData(), SigHashType(), fund_amount,
    WitnessVersion::kVersion0);
  auto own_sig = SignatureUtil::CalculateEcSignature(sig_hash, funding_sk);
  auto pubkeys =
    ScriptUtil::ExtractPubkeysFromMultisigScript(funding_script_pubkey);
  auto own_pubkey_hex = funding_sk.GetPubkey().GetHex();
  if (own_pubkey_hex == pubkeys[0].GetHex()) {
    AddSignaturesForMultiSigInput(
      cet, fund_tx_id, fund_vout, funding_script_pubkey,
      {own_sig, adapted_sig});
  } else if (own_pubkey_hex == pubkeys[1].GetHex()) {
    AddSignaturesForMultiSigInput(
      cet, fund_tx_id, fund_vout, funding_script_pubkey,
      {adapted_sig, own_sig});
  } else {
    throw new CfdException(
      CfdError::kCfdIllegalArgumentError,
      "Public key not part of the multi sig script.");
  }
}

ByteData DlcManager::GetRawFundingTransactionInputSignature(
  const TransactionController &funding_transaction,
  const Privkey &privkey,
  const Txid &prev_tx_id,
  uint32_t prev_tx_vout,
  const Amount &value) {
  auto hash_type = SigHashType();
  auto sig_hash_str = funding_transaction.CreateSignatureHash(
    prev_tx_id, prev_tx_vout, privkey.GeneratePubkey(), hash_type, value,
    WitnessVersion::kVersion0);
  auto sig_hash = ByteData256(sig_hash_str);
  return SignatureUtil::CalculateEcSignature(sig_hash, privkey);
}

void DlcManager::AddSignaturesForMultiSigInput(
  TransactionController *transaction,
  const Txid &prev_tx_id,
  uint32_t prev_tx_vout,
  const Script &multisig_script,
  const std::vector<ByteData> &signatures) {
  std::vector<std::string> signatures_str;
  signatures_str.resize(signatures.size() + 1);

  std::transform(
    signatures.begin(), signatures.end(), signatures_str.begin() + 1,
    [](ByteData data) -> std::string {
      auto hash_type = SigHashType(SigHashAlgorithm::kSigHashAll);
      return CryptoUtil::ConvertSignatureToDer(data.GetHex(), hash_type)
        .GetHex();
    });
  transaction->AddWitnessStack(
    prev_tx_id, prev_tx_vout, signatures_str, multisig_script);
}

void DlcManager::AddSignaturesToRefundTx(
  TransactionController *refund_tx,
  const Script &fund_lockscript,
  const std::vector<ByteData> &signatures,
  const Txid &fund_tx_id,
  const uint32_t fund_tx_vout) {
  AddSignaturesForMultiSigInput(
    refund_tx, fund_tx_id, fund_tx_vout, fund_lockscript, signatures);
}

void DlcManager::AddSignaturesToRefundTx(
  TransactionController *refund_tx,
  const Pubkey &local_pubkey,
  const Pubkey &remote_pubkey,
  const std::vector<ByteData> &signatures,
  const Txid &fund_tx_id,
  const uint32_t fund_tx_vout) {
  auto script = CreateFundTxLockingScript(local_pubkey, remote_pubkey);
  AddSignaturesToRefundTx(
    refund_tx, script, signatures, fund_tx_id, fund_tx_vout);
}

ByteData DlcManager::GetRawTxWitSigAllSignature(
  const TransactionController &transaction,
  const Privkey &privkey,
  const Txid &prev_tx_id,
  uint32_t prev_tx_vout,
  const Script &lockscript,
  const Amount &amount) {
  auto sig_hash_str = transaction.CreateSignatureHash(
    prev_tx_id, prev_tx_vout, lockscript, SigHashType(), amount,
    WitnessVersion::kVersion0);
  auto sig_hash = ByteData256(sig_hash_str);
  return SignatureUtil::CalculateEcSignature(sig_hash, privkey);
}

bool DlcManager::VerifyRefundTxSignature(
  const TransactionController &refund_tx,
  const ByteData &signature,
  const Pubkey &local_pubkey,
  const Pubkey &remote_pubkey,
  const Amount &input_amount,
  bool verify_remote,
  const Txid &fund_txid,
  uint32_t fund_vout) {
  auto lock_script = CreateFundTxLockingScript(local_pubkey, remote_pubkey);
  auto pubkey = verify_remote ? remote_pubkey : local_pubkey;
  return VerifyRefundTxSignature(
    refund_tx, signature, pubkey, lock_script, input_amount, fund_txid,
    fund_vout);
}

bool DlcManager::VerifyRefundTxSignature(
  const TransactionController &refund_tx,
  const ByteData &signature,
  const Pubkey &pubkey,
  const Script &lock_script,
  const Amount &input_amount,
  const Txid &fund_txid,
  uint32_t fund_vout) {
  return refund_tx.VerifyInputSignature(
    signature, pubkey, fund_txid, fund_vout, lock_script, SigHashType(),
    input_amount, WitnessVersion::kVersion0);
}

ByteData DlcManager::GetRawRefundTxSignature(
  const TransactionController &refund_tx,
  const Privkey &privkey,
  const Script &fund_lockscript,
  const Amount &input_amount,
  const Txid &fund_tx_id,
  const uint32_t fund_tx_vout) {
  return GetRawTxWitSigAllSignature(
    refund_tx, privkey, fund_tx_id, fund_tx_vout, fund_lockscript,
    input_amount);
}

ByteData DlcManager::GetRawRefundTxSignature(
  const TransactionController &refund_tx,
  const Privkey &privkey,
  const Pubkey &local_pubkey,
  const Pubkey &remote_pubkey,
  const Amount &input_amount,
  const Txid &fund_tx_id,
  const uint32_t fund_tx_vout) {
  auto script = CreateFundTxLockingScript(local_pubkey, remote_pubkey);
  return GetRawRefundTxSignature(
    refund_tx, privkey, script, input_amount, fund_tx_id, fund_tx_vout);
}

DlcTransactions DlcManager::CreateDlcTransactions(
  const std::vector<DlcOutcome> &outcomes,
  const PartyParams &local_params,
  const PartyParams &remote_params,
  uint64_t refund_locktime,
  uint32_t fee_rate,
  const Address &option_dest,
  const Amount &option_premium,
  uint64_t fund_lock_time,
  uint64_t cet_lock_time,
  uint64_t fund_output_serial_id) {
  auto total_collateral = local_params.collateral + remote_params.collateral;

  for (auto outcome : outcomes) {
    if (outcome.local_payout + outcome.remote_payout != total_collateral) {
      throw CfdException(
        CfdError::kCfdIllegalArgumentError,
        "Sum of outcomes not equal to total collateral.");
    }
  }

  TxOut local_change_output;
  uint64_t local_fund_fee;
  uint64_t local_cet_fee;
  std::tie(local_change_output, local_fund_fee, local_cet_fee) =
    GetChangeOutputAndFees(local_params, fee_rate, option_premium, option_dest);

  TxOut remote_change_output;
  uint64_t remote_fund_fee;
  uint64_t remote_cet_fee;
  std::tie(remote_change_output, remote_fund_fee, remote_cet_fee) =
    GetChangeOutputAndFees(remote_params, fee_rate);

  auto fund_output_value = local_params.input_amount +
                           remote_params.input_amount -
                           local_change_output.GetValue().GetSatoshiValue() -
                           remote_change_output.GetValue().GetSatoshiValue() -
                           local_fund_fee - remote_fund_fee - option_premium;

  if (total_collateral + local_cet_fee + remote_cet_fee != fund_output_value) {
    throw CfdException(
      CfdError::kCfdInternalError, "Fee computation doesn't match.");
  }

  std::vector<TxInputInfo> local_inputs_info;

  for (auto input_info : local_params.inputs_info) {
    local_inputs_info.push_back(input_info);
  }

  std::vector<TxInputInfo> remote_inputs_info;

  for (auto input_info : remote_params.inputs_info) {
    remote_inputs_info.push_back(input_info);
  }

  // refers to public instance
  auto fund_tx = CreateFundTransaction(
    local_params.fund_pubkey, remote_params.fund_pubkey, fund_output_value,
    local_inputs_info, local_change_output, remote_inputs_info,
    remote_change_output, option_dest, option_premium, fund_lock_time,
    local_params.change_serial_id, remote_params.change_serial_id,
    fund_output_serial_id);

  // the given lock time.
  auto fund_tx_id = fund_tx.GetTransaction().GetTxid();

  std::vector<uint64_t> change_serial_ids = {
    fund_output_serial_id, local_params.change_serial_id,
    remote_params.change_serial_id};

  std::sort(change_serial_ids.begin(), change_serial_ids.end());

  uint32_t fund_vout = 0;

  for (size_t i = 0; i < change_serial_ids.size(); i++) {
    if (change_serial_ids[i] == fund_output_serial_id) {
      fund_vout = static_cast<uint32_t>(i);
      break;
    }
  }

  auto cets = CreateCets(
    fund_tx_id, fund_vout, local_params.final_script_pubkey,
    remote_params.final_script_pubkey, outcomes, cet_lock_time,
    local_params.payout_serial_id, remote_params.payout_serial_id);

  auto refund_tx = CreateRefundTransaction(
    local_params.final_script_pubkey, remote_params.final_script_pubkey,
    local_params.collateral, remote_params.collateral, refund_locktime,
    fund_tx_id, fund_vout);

  return {fund_tx, cets, refund_tx};
}

BatchDlcTransactions DlcManager::CreateBatchDlcTransactions(
  const std::vector<std::vector<DlcOutcome>> &outcomes_list,
  const BatchPartyParams &local_params,
  const BatchPartyParams &remote_params,
  std::vector<uint64_t> refund_locktimes,
  uint32_t fee_rate,
  const uint64_t fund_lock_time,
  const uint64_t cet_lock_time,
  const std::vector<uint64_t> &fund_output_serial_ids) {
  if (
    outcomes_list.size() != local_params.fund_pubkeys.size() ||
    outcomes_list.size() != remote_params.fund_pubkeys.size()) {
    throw CfdException(
      CfdError::kCfdIllegalArgumentError,
      "Number of outcomes, local params, and remote params must be equal.");
  }

  for (size_t i = 0; i < outcomes_list.size(); i++) {
    auto outcomes = outcomes_list[i];
    auto total_collateral =
      local_params.collaterals[i] + remote_params.collaterals[i];

    for (auto outcome : outcomes) {
      if (outcome.local_payout + outcome.remote_payout != total_collateral) {
        throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "Sum of outcomes not equal to total collateral.");
      }
    }
  }

  TxOut local_change_output;
  uint64_t local_fund_fees;
  uint64_t local_cet_fees;
  std::tie(local_change_output, local_fund_fees, local_cet_fees) =
    GetBatchChangeOutputAndFees(local_params, fee_rate);

  TxOut remote_change_output;
  uint64_t remote_fund_fees;
  uint64_t remote_cet_fees;
  std::tie(remote_change_output, remote_fund_fees, remote_cet_fees) =
    GetBatchChangeOutputAndFees(remote_params, fee_rate);

  auto local_cet_fee = ceil(
    static_cast<double>(local_cet_fees) /
    static_cast<double>(outcomes_list.size()));
  auto remote_cet_fee = ceil(
    static_cast<double>(remote_cet_fees) /
    static_cast<double>(outcomes_list.size()));

  std::vector<Amount> fund_output_values;
  for (size_t i = 0; i < local_params.collaterals.size(); i++) {
    auto fund_output_value = local_params.collaterals[i] +
                             remote_params.collaterals[i] + local_cet_fee +
                             remote_cet_fee;
    fund_output_values.push_back(fund_output_value);
  }

  auto total_fund_output_value = std::accumulate(
    fund_output_values.begin(), fund_output_values.end(), Amount(0));

  auto total_collateral = std::accumulate(
                            local_params.collaterals.begin(),
                            local_params.collaterals.end(), Amount(0)) +
                          std::accumulate(
                            remote_params.collaterals.begin(),
                            remote_params.collaterals.end(), Amount(0));

  auto collateral_and_fees =
    total_collateral + local_cet_fees + remote_cet_fees;

  auto collateral_diff = std::abs(
    collateral_and_fees.GetSatoshiValue() -
    total_fund_output_value.GetSatoshiValue());

  if (collateral_diff > 20) {
    std::cerr << "collateral_and_fees: "
              << collateral_and_fees.GetSatoshiValue() << std::endl;
    std::cerr << "total_fund_output_value: "
              << total_fund_output_value.GetSatoshiValue() << std::endl;
    throw CfdException(
      CfdError::kCfdInternalError,
      "Fee computation doesn't match for collateral. The values must be within "
      "20 satoshis of each other.");
  }

  std::vector<TxInputInfo> local_inputs_info;

  for (auto input_info : local_params.inputs_info) {
    local_inputs_info.push_back(input_info);
  }

  std::vector<TxInputInfo> remote_inputs_info;

  for (auto input_info : remote_params.inputs_info) {
    remote_inputs_info.push_back(input_info);
  }

  // refers to public instance
  auto fund_tx = CreateBatchFundTransaction(
    local_params.fund_pubkeys, remote_params.fund_pubkeys, fund_output_values,
    local_inputs_info, local_change_output, remote_inputs_info,
    remote_change_output, fund_lock_time, local_params.change_serial_id,
    remote_params.change_serial_id, fund_output_serial_ids);

  // the given lock time.
  auto fund_tx_id = fund_tx.GetTransaction().GetTxid();

  // set fund_vouts to empty array
  std::vector<uint64_t> fund_vouts;

  // if fund_output_serial_ids is empty, fund_vouts should be in order
  if (fund_output_serial_ids.empty()) {
    for (size_t i = 0; i < fund_output_values.size(); i++) {
      fund_vouts.push_back(i);
    }
  } else {
    // set change_serial_ids to fund_output_serial_ids and change_serial_ids and
    // sort
    std::vector<uint64_t> change_serial_ids = fund_output_serial_ids;
    change_serial_ids.push_back(local_params.change_serial_id);
    change_serial_ids.push_back(remote_params.change_serial_id);
    std::sort(change_serial_ids.begin(), change_serial_ids.end());

    // set fund_vouts to empty array
    fund_vouts.resize(fund_output_serial_ids.size());

    // set fund_vouts to the index of fund_output_serial_ids in
    // change_serial_ids
    for (size_t i = 0; i < fund_output_serial_ids.size(); i++) {
      for (size_t j = 0; j < change_serial_ids.size(); j++) {
        if (fund_output_serial_ids[i] == change_serial_ids[j]) {
          fund_vouts[i] = j;
          break;
        }
      }
    }
  }

  std::vector<std::vector<TransactionController>> cets_list;
  std::vector<TransactionController> refund_txs;

  for (size_t i = 0; i < fund_vouts.size(); i++) {
    auto cets = CreateCets(
      fund_tx_id, fund_vouts[i], local_params.final_script_pubkeys[i],
      remote_params.final_script_pubkeys[i], outcomes_list[i], cet_lock_time,
      local_params.payout_serial_ids[i], remote_params.payout_serial_ids[i]);

    cets_list.push_back(cets);

    auto refund_tx = CreateRefundTransaction(
      local_params.final_script_pubkeys[i],
      remote_params.final_script_pubkeys[i], local_params.collaterals[i],
      remote_params.collaterals[i], refund_locktimes[i], fund_tx_id,
      fund_vouts[i]);

    refund_txs.push_back(refund_tx);
  }

  return {fund_tx, cets_list, refund_txs};
}

uint32_t DlcManager::GetTotalInputVSize(const std::vector<TxIn> &inputs) {
  uint32_t total_size = 0;
  for (auto it = inputs.begin(); it != inputs.end(); ++it) {
    uint32_t witness_size;
    uint32_t full_size = it->EstimateTxInSize(
      AddressType::kP2wpkhAddress, Script(), &witness_size);
    total_size += AbstractTransaction::GetVsizeFromSize(
      full_size - witness_size, witness_size);
  }

  return total_size;
}

bool DlcManager::IsDustOutput(const TxOut &output) {
  return output.GetValue() < DUST_LIMIT;
}

bool DlcManager::IsDustOutputInfo(const TxOutputInfo &output) {
  return output.value < DUST_LIMIT;
}

static uint32_t GetInputsWeight(const std::vector<TxInputInfo> &inputs_info) {
  uint32_t total = 0;
  for (auto input_info : inputs_info) {
    auto script = input_info.input.GetUnlockingScript();
    auto script_size = script.IsEmpty() ? 0 : script.GetData().GetDataSize();
    total += 164 + 4 * script_size + input_info.max_witness_length;
  }

  return total;
}

std::tuple<TxOut, uint64_t, uint64_t> DlcManager::GetChangeOutputAndFees(
  const PartyParams &params,
  uint64_t fee_rate,
  Amount option_premium,
  Address option_dest) {
  auto inputs_size = GetInputsWeight(params.inputs_info);
  auto change_size = params.change_script_pubkey.GetData().GetDataSize();
  double fund_weight =
    (FUND_TX_BASE_WEIGHT / 2 + inputs_size + change_size * 4 + 36);
  if (option_premium.GetSatoshiValue() > 0) {
    if (option_dest.GetAddress() == "") {
      throw CfdException(
        CfdError::kCfdIllegalArgumentError,
        "An destination address for the premium is required when the option "
        "premium amount is greater than zero.");
    }
    fund_weight +=
      36 + option_dest.GetLockingScript().GetData().GetDataSize() * 4;
  }
  auto fund_fee = ceil(fund_weight / 4) * fee_rate;
  double cet_weight =
    (CET_BASE_WEIGHT / 2 +
     params.final_script_pubkey.GetData().GetDataSize() * 4);
  auto cet_fee = ceil(cet_weight / 4) * fee_rate;
  auto fund_out = params.collateral + fund_fee + cet_fee;
  if (params.input_amount < (fund_out + option_premium)) {
    throw CfdException(
      CfdError::kCfdIllegalArgumentError,
      "Input amount smaller than required for collateral, "
      "fees and option premium.");
  }

  TxOut change_output(
    params.input_amount - fund_out - option_premium,
    params.change_script_pubkey);

  return std::make_tuple(change_output, fund_fee, cet_fee);
}

std::tuple<TxOut, uint64_t, uint64_t> DlcManager::GetBatchChangeOutputAndFees(
  const BatchPartyParams &params, uint64_t fee_rate) {
  auto inputs_size = GetInputsWeight(params.inputs_info);
  auto change_size = params.change_script_pubkey.GetData().GetDataSize();
  double fund_weight =
    ((BATCH_FUND_TX_BASE_WEIGHT +
      (FUNDING_OUTPUT_SIZE * params.fund_pubkeys.size() * 4)) /
       2 +
     inputs_size + change_size * 4 + 36);
  auto fund_fee = ceil(fund_weight / 4) * fee_rate;
  double cet_weight = 0;
  for (const auto &final_script_pubkey : params.final_script_pubkeys) {
    cet_weight +=
      (CET_BASE_WEIGHT / 2 + final_script_pubkey.GetData().GetDataSize() * 4);
  }
  auto cet_fee = ceil(cet_weight / 4) * fee_rate;

  Amount collateral = std::accumulate(
    params.collaterals.begin(), params.collaterals.end(), Amount(0));

  auto fund_out = collateral + fund_fee + cet_fee;
  if (params.input_amount < fund_out) {
    throw CfdException(
      CfdError::kCfdIllegalArgumentError,
      "Input amount smaller than required for collateral, "
      "fees and option premium.");
  }

  TxOut change_output(
    params.input_amount - fund_out, params.change_script_pubkey);

  return std::make_tuple(change_output, fund_fee, cet_fee);
}

Pubkey DlcManager::ComputeAdaptorPoint(
  const std::vector<ByteData256> &msgs,
  const std::vector<SchnorrPubkey> &r_values,
  const SchnorrPubkey &pubkey) {
  if (r_values.size() != msgs.size()) {
    throw CfdException(
      CfdError::kCfdIllegalArgumentError,
      "Number of r values and messages must match.");
  }

  if (msgs.size() == 1) {
    return SchnorrUtil::ComputeSigPoint(msgs[0], r_values[0], pubkey);
  }

  return SchnorrUtil::ComputeSigPointBatch(msgs, r_values, pubkey);
}
}  // namespace dlc
}  // namespace cfd
