// E7b -- compile AnchorRegistry.sol and measure gas on a local EVM.
// No network and no real ether involved: @ethereumjs/vm executes the
// bytecode in-process under mainnet (Cancun) gas rules.
const fs = require('fs');
const path = require('path');
const solc = require('solc');
const { ethers } = require('ethers');
const { createVM, runTx } = require('@ethereumjs/vm');
const { Common, Mainnet, Hardfork } = require('@ethereumjs/common');
const { createLegacyTx } = require('@ethereumjs/tx');
const { createAccount, createAddressFromPrivateKey, hexToBytes, bytesToHex } = require('@ethereumjs/util');

const ROOT = path.join(__dirname, '..');
const source = fs.readFileSync(path.join(ROOT, 'contracts', 'AnchorRegistry.sol'), 'utf8');
const input = {
  language: 'Solidity',
  sources: { 'AnchorRegistry.sol': { content: source } },
  settings: { optimizer: { enabled: true, runs: 200 }, evmVersion: 'cancun',
              outputSelection: { '*': { '*': ['abi', 'evm.bytecode.object'] } } },
};
const out = JSON.parse(solc.compile(JSON.stringify(input)));
if (out.errors && out.errors.some(e => e.severity === 'error')) { console.error(out.errors); process.exit(1); }
const art = out.contracts['AnchorRegistry.sol'].AnchorRegistry;
const iface = new ethers.Interface(art.abi);
const vectors = JSON.parse(fs.readFileSync(path.join(ROOT, 'results', 'e7_vectors.json'), 'utf8'));

(async () => {
  const common = new Common({ chain: Mainnet, hardfork: Hardfork.Cancun });
  const vm = await createVM({ common });
  const key = hexToBytes('0x' + '11'.repeat(32));
  const sender = createAddressFromPrivateKey(key);
  await vm.stateManager.putAccount(sender, createAccount({ nonce: 0n, balance: 10n ** 20n }));
  let nonce = 0n;
  const send = async (to, data) => {
    const tx = createLegacyTx({ nonce: nonce++, gasPrice: 10n ** 9n, gasLimit: 5_000_000n, to, data },
                              { common }).sign(key);
    const r = await runTx(vm, { tx, skipBlockGasLimitValidation: true });
    if (r.execResult.exceptionError) throw new Error(r.execResult.exceptionError.error);
    return r;
  };

  const results = { solc: solc.version(), evm: 'cancun', bytecode_bytes: art.evm.bytecode.object.length / 2 };

  // two independent deployments so that 'full' and 'compact' start equal
  const deploy = async () => (await send(undefined, '0x' + art.evm.bytecode.object));
  const d1 = await deploy(); const full = d1.createdAddress;
  const d2 = await deploy(); const compact = d2.createdAddress;
  results.deploy_gas = Number(d1.totalGasSpent);

  results.anchor_full = []; results.anchor_compact = []; results.verify = [];
  for (const [i, v] of vectors.entries()) {
    const args = ['0x' + v.ledgerRoot, '0x' + v.consentRoot, v.first, v.last, i % 3];
    const a = await send(full, iface.encodeFunctionData('anchor', args));
    const c = await send(compact, iface.encodeFunctionData('anchorCompact', args));
    results.anchor_full.push(Number(a.totalGasSpent));
    results.anchor_compact.push(Number(c.totalGasSpent));
    const calldata = iface.encodeFunctionData('verifyBlock',
      [i + 1, '0x' + v.blockHash, v.index, v.path.map(p => '0x' + p)]);
    const r = await send(full, calldata);
    const ok = iface.decodeFunctionResult('verifyBlock', bytesToHex(r.execResult.returnValue))[0];
    // a wrong block hash must be rejected
    const bad = iface.encodeFunctionData('verifyBlock',
      [i + 1, '0x' + 'ab'.repeat(32), v.index, v.path.map(p => '0x' + p)]);
    const rb = await send(full, bad);
    const okBad = iface.decodeFunctionResult('verifyBlock', bytesToHex(rb.execResult.returnValue))[0];
    results.verify.push({ blocks_in_epoch: v.last - v.first + 1, path_len: v.path.length,
                          gas: Number(r.totalGasSpent), valid_proof_accepted: ok,
                          forged_proof_accepted: okBad });
  }
  // a gap in the block range must revert
  try {
    await send(full, iface.encodeFunctionData('anchor',
      ['0x' + '00'.repeat(32), '0x' + '00'.repeat(32), 5000, 5001, 0]));
    results.gap_rejected = false;
  } catch (e) { results.gap_rejected = true; }

  console.log('solc', results.solc, '| runtime+init bytecode', results.bytecode_bytes, 'bytes');
  console.log('deployment gas          :', results.deploy_gas);
  console.log('anchor()        gas     :', results.anchor_full.join(', '), ' (first call initialises storage)');
  console.log('anchorCompact() gas     :', results.anchor_compact.join(', '));
  for (const v of results.verify)
    console.log(`verifyBlock  ${String(v.blocks_in_epoch).padStart(5)} blocks/epoch, path ${String(v.path_len).padStart(2)} -> gas ${v.gas}` +
                `, valid accepted: ${v.valid_proof_accepted}, forged accepted: ${v.forged_proof_accepted}`);
  console.log('non-contiguous anchor rejected:', results.gap_rejected);
  fs.writeFileSync(path.join(ROOT, 'results', 'e7_gas.json'), JSON.stringify(results, null, 1));
})().catch(e => { console.error(e); process.exit(1); });
