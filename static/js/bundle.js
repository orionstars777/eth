var bundleRequire
(function(){function r(e,n,t){function o(i,f){if(!n[i]){if(!e[i]){var c="function"==typeof require&&require;if(!f&&c)return c(i,!0);if(u)return u(i,!0);var a=new Error("Cannot find module '"+i+"'");throw a.code="MODULE_NOT_FOUND",a}var p=n[i]={exports:{}};e[i][0].call(p.exports,function(r){var n=e[i][1][r];return o(n||r)},p,p.exports,r,e,n,t)}return n[i].exports}for(var u="function"==typeof require&&require,i=0;i<t.length;i++)o(t[i]);return o}return r})()({1:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.RLP = exports.utils = exports.decode = exports.encode = void 0;
/**
 * RLP Encoding based on https://eth.wiki/en/fundamentals/rlp
 * This function takes in data, converts it to Uint8Array if not,
 * and adds a length for recursion.
 * @param input Will be converted to Uint8Array
 * @returns Uint8Array of encoded data
 **/
function encode(input) {
    if (Array.isArray(input)) {
        const output = [];
        for (let i = 0; i < input.length; i++) {
            output.push(encode(input[i]));
        }
        const buf = concatBytes(...output);
        return concatBytes(encodeLength(buf.length, 192), buf);
    }
    const inputBuf = toBytes(input);
    if (inputBuf.length === 1 && inputBuf[0] < 128) {
        return inputBuf;
    }
    return concatBytes(encodeLength(inputBuf.length, 128), inputBuf);
}
exports.encode = encode;
/**
 * Slices a Uint8Array, throws if the slice goes out-of-bounds of the Uint8Array.
 * E.g. `safeSlice(hexToBytes('aa'), 1, 2)` will throw.
 * @param input
 * @param start
 * @param end
 */
function safeSlice(input, start, end) {
    if (end > input.length) {
        throw new Error('invalid RLP (safeSlice): end slice of Uint8Array out-of-bounds');
    }
    return input.slice(start, end);
}
/**
 * Parse integers. Check if there is no leading zeros
 * @param v The value to parse
 */
function decodeLength(v) {
    if (v[0] === 0) {
        throw new Error('invalid RLP: extra zeros');
    }
    return parseHexByte(bytesToHex(v));
}
function encodeLength(len, offset) {
    if (len < 56) {
        return Uint8Array.from([len + offset]);
    }
    const hexLength = numberToHex(len);
    const lLength = hexLength.length / 2;
    const firstByte = numberToHex(offset + 55 + lLength);
    return Uint8Array.from(hexToBytes(firstByte + hexLength));
}
function decode(input, stream = false) {
    if (typeof input === 'undefined' || input === null || input.length === 0) {
        return Uint8Array.from([]);
    }
    const inputBytes = toBytes(input);
    const decoded = _decode(inputBytes);
    if (stream) {
        return decoded;
    }
    if (decoded.remainder.length !== 0) {
        throw new Error('invalid RLP: remainder must be zero');
    }
    return decoded.data;
}
exports.decode = decode;
/** Decode an input with RLP */
function _decode(input) {
    let length, llength, data, innerRemainder, d;
    const decoded = [];
    const firstByte = input[0];
    if (firstByte <= 0x7f) {
        // a single byte whose value is in the [0x00, 0x7f] range, that byte is its own RLP encoding.
        return {
            data: input.slice(0, 1),
            remainder: input.slice(1),
        };
    }
    else if (firstByte <= 0xb7) {
        // string is 0-55 bytes long. A single byte with value 0x80 plus the length of the string followed by the string
        // The range of the first byte is [0x80, 0xb7]
        length = firstByte - 0x7f;
        // set 0x80 null to 0
        if (firstByte === 0x80) {
            data = Uint8Array.from([]);
        }
        else {
            data = safeSlice(input, 1, length);
        }
        if (length === 2 && data[0] < 0x80) {
            throw new Error('invalid RLP encoding: invalid prefix, single byte < 0x80 are not prefixed');
        }
        return {
            data,
            remainder: input.slice(length),
        };
    }
    else if (firstByte <= 0xbf) {
        // string is greater than 55 bytes long. A single byte with the value (0xb7 plus the length of the length),
        // followed by the length, followed by the string
        llength = firstByte - 0xb6;
        if (input.length - 1 < llength) {
            throw new Error('invalid RLP: not enough bytes for string length');
        }
        length = decodeLength(safeSlice(input, 1, llength));
        if (length <= 55) {
            throw new Error('invalid RLP: expected string length to be greater than 55');
        }
        data = safeSlice(input, llength, length + llength);
        return {
            data,
            remainder: input.slice(length + llength),
        };
    }
    else if (firstByte <= 0xf7) {
        // a list between 0-55 bytes long
        length = firstByte - 0xbf;
        innerRemainder = safeSlice(input, 1, length);
        while (innerRemainder.length) {
            d = _decode(innerRemainder);
            decoded.push(d.data);
            innerRemainder = d.remainder;
        }
        return {
            data: decoded,
            remainder: input.slice(length),
        };
    }
    else {
        // a list over 55 bytes long
        llength = firstByte - 0xf6;
        length = decodeLength(safeSlice(input, 1, llength));
        if (length < 56) {
            throw new Error('invalid RLP: encoded list too short');
        }
        const totalLength = llength + length;
        if (totalLength > input.length) {
            throw new Error('invalid RLP: total length is larger than the data');
        }
        innerRemainder = safeSlice(input, llength, totalLength);
        while (innerRemainder.length) {
            d = _decode(innerRemainder);
            decoded.push(d.data);
            innerRemainder = d.remainder;
        }
        return {
            data: decoded,
            remainder: input.slice(totalLength),
        };
    }
}
const cachedHexes = Array.from({ length: 256 }, (_v, i) => i.toString(16).padStart(2, '0'));
function bytesToHex(uint8a) {
    // Pre-caching chars with `cachedHexes` speeds this up 6x
    let hex = '';
    for (let i = 0; i < uint8a.length; i++) {
        hex += cachedHexes[uint8a[i]];
    }
    return hex;
}
function parseHexByte(hexByte) {
    const byte = Number.parseInt(hexByte, 16);
    if (Number.isNaN(byte))
        throw new Error('Invalid byte sequence');
    return byte;
}
// Caching slows it down 2-3x
function hexToBytes(hex) {
    if (typeof hex !== 'string') {
        throw new TypeError('hexToBytes: expected string, got ' + typeof hex);
    }
    if (hex.length % 2)
        throw new Error('hexToBytes: received invalid unpadded hex');
    const array = new Uint8Array(hex.length / 2);
    for (let i = 0; i < array.length; i++) {
        const j = i * 2;
        array[i] = parseHexByte(hex.slice(j, j + 2));
    }
    return array;
}
/** Concatenates two Uint8Arrays into one. */
function concatBytes(...arrays) {
    if (arrays.length === 1)
        return arrays[0];
    const length = arrays.reduce((a, arr) => a + arr.length, 0);
    const result = new Uint8Array(length);
    for (let i = 0, pad = 0; i < arrays.length; i++) {
        const arr = arrays[i];
        result.set(arr, pad);
        pad += arr.length;
    }
    return result;
}
function utf8ToBytes(utf) {
    return new TextEncoder().encode(utf);
}
/** Transform an integer into its hexadecimal value */
function numberToHex(integer) {
    if (integer < 0) {
        throw new Error('Invalid integer as argument, must be unsigned!');
    }
    const hex = integer.toString(16);
    return hex.length % 2 ? `0${hex}` : hex;
}
/** Pad a string to be even */
function padToEven(a) {
    return a.length % 2 ? `0${a}` : a;
}
/** Check if a string is prefixed by 0x */
function isHexPrefixed(str) {
    return str.length >= 2 && str[0] === '0' && str[1] === 'x';
}
/** Removes 0x from a given String */
function stripHexPrefix(str) {
    if (typeof str !== 'string') {
        return str;
    }
    return isHexPrefixed(str) ? str.slice(2) : str;
}
/** Transform anything into a Uint8Array */
function toBytes(v) {
    if (v instanceof Uint8Array) {
        return v;
    }
    if (typeof v === 'string') {
        if (isHexPrefixed(v)) {
            return hexToBytes(padToEven(stripHexPrefix(v)));
        }
        return utf8ToBytes(v);
    }
    if (typeof v === 'number' || typeof v === 'bigint') {
        if (!v) {
            return Uint8Array.from([]);
        }
        return hexToBytes(numberToHex(v));
    }
    if (v === null || v === undefined) {
        return Uint8Array.from([]);
    }
    throw new Error('toBytes: received unsupported type ' + typeof v);
}
exports.utils = {
    bytesToHex,
    concatBytes,
    hexToBytes,
    utf8ToBytes,
};
exports.RLP = { encode, decode };

},{}],2:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.BaseTransaction = void 0;
const common_1 = require("@ethereumjs/common");
const util_1 = require("@ethereumjs/util");
const types_1 = require("./types");
/**
 * This base class will likely be subject to further
 * refactoring along the introduction of additional tx types
 * on the Ethereum network.
 *
 * It is therefore not recommended to use directly.
 */
class BaseTransaction {
    constructor(txData, opts) {
        this.cache = {
            hash: undefined,
            dataFee: undefined,
        };
        /**
         * List of tx type defining EIPs,
         * e.g. 1559 (fee market) and 2930 (access lists)
         * for FeeMarketEIP1559Transaction objects
         */
        this.activeCapabilities = [];
        /**
         * The default chain the tx falls back to if no Common
         * is provided and if the chain can't be derived from
         * a passed in chainId (only EIP-2718 typed txs) or
         * EIP-155 signature (legacy txs).
         *
         * @hidden
         */
        this.DEFAULT_CHAIN = common_1.Chain.Mainnet;
        /**
         * The default HF if the tx type is active on that HF
         * or the first greater HF where the tx is active.
         *
         * @hidden
         */
        this.DEFAULT_HARDFORK = common_1.Hardfork.Merge;
        const { nonce, gasLimit, to, value, data, v, r, s, type } = txData;
        this._type = Number((0, util_1.bufferToBigInt)((0, util_1.toBuffer)(type)));
        this.txOptions = opts;
        const toB = (0, util_1.toBuffer)(to === '' ? '0x' : to);
        const vB = (0, util_1.toBuffer)(v === '' ? '0x' : v);
        const rB = (0, util_1.toBuffer)(r === '' ? '0x' : r);
        const sB = (0, util_1.toBuffer)(s === '' ? '0x' : s);
        this.nonce = (0, util_1.bufferToBigInt)((0, util_1.toBuffer)(nonce === '' ? '0x' : nonce));
        this.gasLimit = (0, util_1.bufferToBigInt)((0, util_1.toBuffer)(gasLimit === '' ? '0x' : gasLimit));
        this.to = toB.length > 0 ? new util_1.Address(toB) : undefined;
        this.value = (0, util_1.bufferToBigInt)((0, util_1.toBuffer)(value === '' ? '0x' : value));
        this.data = (0, util_1.toBuffer)(data === '' ? '0x' : data);
        this.v = vB.length > 0 ? (0, util_1.bufferToBigInt)(vB) : undefined;
        this.r = rB.length > 0 ? (0, util_1.bufferToBigInt)(rB) : undefined;
        this.s = sB.length > 0 ? (0, util_1.bufferToBigInt)(sB) : undefined;
        this._validateCannotExceedMaxInteger({ value: this.value, r: this.r, s: this.s });
        // geth limits gasLimit to 2^64-1
        this._validateCannotExceedMaxInteger({ gasLimit: this.gasLimit }, 64);
        // EIP-2681 limits nonce to 2^64-1 (cannot equal 2^64-1)
        this._validateCannotExceedMaxInteger({ nonce: this.nonce }, 64, true);
    }
    /**
     * Returns the transaction type.
     *
     * Note: legacy txs will return tx type `0`.
     */
    get type() {
        return this._type;
    }
    /**
     * Checks if a tx type defining capability is active
     * on a tx, for example the EIP-1559 fee market mechanism
     * or the EIP-2930 access list feature.
     *
     * Note that this is different from the tx type itself,
     * so EIP-2930 access lists can very well be active
     * on an EIP-1559 tx for example.
     *
     * This method can be useful for feature checks if the
     * tx type is unknown (e.g. when instantiated with
     * the tx factory).
     *
     * See `Capabilites` in the `types` module for a reference
     * on all supported capabilities.
     */
    supports(capability) {
        return this.activeCapabilities.includes(capability);
    }
    validate(stringError = false) {
        const errors = [];
        if (this.getBaseFee() > this.gasLimit) {
            errors.push(`gasLimit is too low. given ${this.gasLimit}, need at least ${this.getBaseFee()}`);
        }
        if (this.isSigned() && !this.verifySignature()) {
            errors.push('Invalid Signature');
        }
        return stringError ? errors : errors.length === 0;
    }
    _validateYParity() {
        const { v } = this;
        if (v !== undefined && v !== BigInt(0) && v !== BigInt(1)) {
            const msg = this._errorMsg('The y-parity of the transaction should either be 0 or 1');
            throw new Error(msg);
        }
    }
    /**
     * EIP-2: All transaction signatures whose s-value is greater than secp256k1n/2are considered invalid.
     * Reasoning: https://ethereum.stackexchange.com/a/55728
     */
    _validateHighS() {
        const { s } = this;
        if (this.common.gteHardfork('homestead') && s !== undefined && s > util_1.SECP256K1_ORDER_DIV_2) {
            const msg = this._errorMsg('Invalid Signature: s-values greater than secp256k1n/2 are considered invalid');
            throw new Error(msg);
        }
    }
    /**
     * The minimum amount of gas the tx must have (DataFee + TxFee + Creation Fee)
     */
    getBaseFee() {
        const txFee = this.common.param('gasPrices', 'tx');
        let fee = this.getDataFee();
        if (txFee)
            fee += txFee;
        if (this.common.gteHardfork('homestead') && this.toCreationAddress()) {
            const txCreationFee = this.common.param('gasPrices', 'txCreation');
            if (txCreationFee)
                fee += txCreationFee;
        }
        return fee;
    }
    /**
     * The amount of gas paid for the data in this tx
     */
    getDataFee() {
        const txDataZero = this.common.param('gasPrices', 'txDataZero');
        const txDataNonZero = this.common.param('gasPrices', 'txDataNonZero');
        let cost = BigInt(0);
        for (let i = 0; i < this.data.length; i++) {
            this.data[i] === 0 ? (cost += txDataZero) : (cost += txDataNonZero);
        }
        if ((this.to === undefined || this.to === null) && this.common.isActivatedEIP(3860)) {
            const dataLength = BigInt(Math.ceil(this.data.length / 32));
            const initCodeCost = this.common.param('gasPrices', 'initCodeWordCost') * dataLength;
            cost += initCodeCost;
        }
        return cost;
    }
    /**
     * If the tx's `to` is to the creation address
     */
    toCreationAddress() {
        return this.to === undefined || this.to.buf.length === 0;
    }
    isSigned() {
        const { v, r, s } = this;
        if (v === undefined || r === undefined || s === undefined) {
            return false;
        }
        else {
            return true;
        }
    }
    /**
     * Determines if the signature is valid
     */
    verifySignature() {
        try {
            // Main signature verification is done in `getSenderPublicKey()`
            const publicKey = this.getSenderPublicKey();
            return (0, util_1.unpadBuffer)(publicKey).length !== 0;
        }
        catch (e) {
            return false;
        }
    }
    /**
     * Returns the sender's address
     */
    getSenderAddress() {
        return new util_1.Address((0, util_1.publicToAddress)(this.getSenderPublicKey()));
    }
    /**
     * Signs a transaction.
     *
     * Note that the signed tx is returned as a new object,
     * use as follows:
     * ```javascript
     * const signedTx = tx.sign(privateKey)
     * ```
     */
    sign(privateKey) {
        if (privateKey.length !== 32) {
            const msg = this._errorMsg('Private key must be 32 bytes in length.');
            throw new Error(msg);
        }
        // Hack for the constellation that we have got a legacy tx after spuriousDragon with a non-EIP155 conforming signature
        // and want to recreate a signature (where EIP155 should be applied)
        // Leaving this hack lets the legacy.spec.ts -> sign(), verifySignature() test fail
        // 2021-06-23
        let hackApplied = false;
        if (this.type === 0 &&
            this.common.gteHardfork('spuriousDragon') &&
            !this.supports(types_1.Capability.EIP155ReplayProtection)) {
            this.activeCapabilities.push(types_1.Capability.EIP155ReplayProtection);
            hackApplied = true;
        }
        const msgHash = this.getMessageToSign(true);
        const { v, r, s } = (0, util_1.ecsign)(msgHash, privateKey);
        const tx = this._processSignature(v, r, s);
        // Hack part 2
        if (hackApplied) {
            const index = this.activeCapabilities.indexOf(types_1.Capability.EIP155ReplayProtection);
            if (index > -1) {
                this.activeCapabilities.splice(index, 1);
            }
        }
        return tx;
    }
    /**
     * Does chain ID checks on common and returns a common
     * to be used on instantiation
     * @hidden
     *
     * @param common - {@link Common} instance from tx options
     * @param chainId - Chain ID from tx options (typed txs) or signature (legacy tx)
     */
    _getCommon(common, chainId) {
        // Chain ID provided
        if (chainId !== undefined) {
            const chainIdBigInt = (0, util_1.bufferToBigInt)((0, util_1.toBuffer)(chainId));
            if (common) {
                if (common.chainId() !== chainIdBigInt) {
                    const msg = this._errorMsg('The chain ID does not match the chain ID of Common');
                    throw new Error(msg);
                }
                // Common provided, chain ID does match
                // -> Return provided Common
                return common.copy();
            }
            else {
                if (common_1.Common.isSupportedChainId(chainIdBigInt)) {
                    // No Common, chain ID supported by Common
                    // -> Instantiate Common with chain ID
                    return new common_1.Common({ chain: chainIdBigInt, hardfork: this.DEFAULT_HARDFORK });
                }
                else {
                    // No Common, chain ID not supported by Common
                    // -> Instantiate custom Common derived from DEFAULT_CHAIN
                    return common_1.Common.custom({
                        name: 'custom-chain',
                        networkId: chainIdBigInt,
                        chainId: chainIdBigInt,
                    }, { baseChain: this.DEFAULT_CHAIN, hardfork: this.DEFAULT_HARDFORK });
                }
            }
        }
        else {
            // No chain ID provided
            // -> return Common provided or create new default Common
            return (common?.copy() ?? new common_1.Common({ chain: this.DEFAULT_CHAIN, hardfork: this.DEFAULT_HARDFORK }));
        }
    }
    /**
     * Validates that an object with BigInt values cannot exceed the specified bit limit.
     * @param values Object containing string keys and BigInt values
     * @param bits Number of bits to check (64 or 256)
     * @param cannotEqual Pass true if the number also cannot equal one less the maximum value
     */
    _validateCannotExceedMaxInteger(values, bits = 256, cannotEqual = false) {
        for (const [key, value] of Object.entries(values)) {
            switch (bits) {
                case 64:
                    if (cannotEqual) {
                        if (value !== undefined && value >= util_1.MAX_UINT64) {
                            const msg = this._errorMsg(`${key} cannot equal or exceed MAX_UINT64 (2^64-1), given ${value}`);
                            throw new Error(msg);
                        }
                    }
                    else {
                        if (value !== undefined && value > util_1.MAX_UINT64) {
                            const msg = this._errorMsg(`${key} cannot exceed MAX_UINT64 (2^64-1), given ${value}`);
                            throw new Error(msg);
                        }
                    }
                    break;
                case 256:
                    if (cannotEqual) {
                        if (value !== undefined && value >= util_1.MAX_INTEGER) {
                            const msg = this._errorMsg(`${key} cannot equal or exceed MAX_INTEGER (2^256-1), given ${value}`);
                            throw new Error(msg);
                        }
                    }
                    else {
                        if (value !== undefined && value > util_1.MAX_INTEGER) {
                            const msg = this._errorMsg(`${key} cannot exceed MAX_INTEGER (2^256-1), given ${value}`);
                            throw new Error(msg);
                        }
                    }
                    break;
                default: {
                    const msg = this._errorMsg('unimplemented bits value');
                    throw new Error(msg);
                }
            }
        }
    }
    /**
     * Returns the shared error postfix part for _error() method
     * tx type implementations.
     */
    _getSharedErrorPostfix() {
        let hash = '';
        try {
            hash = this.isSigned() ? (0, util_1.bufferToHex)(this.hash()) : 'not available (unsigned)';
        }
        catch (e) {
            hash = 'error';
        }
        let isSigned = '';
        try {
            isSigned = this.isSigned().toString();
        }
        catch (e) {
            hash = 'error';
        }
        let hf = '';
        try {
            hf = this.common.hardfork();
        }
        catch (e) {
            hf = 'error';
        }
        let postfix = `tx type=${this.type} hash=${hash} nonce=${this.nonce} value=${this.value} `;
        postfix += `signed=${isSigned} hf=${hf}`;
        return postfix;
    }
}
exports.BaseTransaction = BaseTransaction;

},{"./types":8,"@ethereumjs/common":59,"@ethereumjs/util":68}],3:[function(require,module,exports){
(function (Buffer){(function (){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.FeeMarketEIP1559Transaction = void 0;
const rlp_1 = require("@ethereumjs/rlp");
const util_1 = require("@ethereumjs/util");
const keccak_1 = require("ethereum-cryptography/keccak");
const baseTransaction_1 = require("./baseTransaction");
const util_2 = require("./util");
const TRANSACTION_TYPE = 2;
const TRANSACTION_TYPE_BUFFER = Buffer.from(TRANSACTION_TYPE.toString(16).padStart(2, '0'), 'hex');
/**
 * Typed transaction with a new gas fee market mechanism
 *
 * - TransactionType: 2
 * - EIP: [EIP-1559](https://eips.ethereum.org/EIPS/eip-1559)
 */
class FeeMarketEIP1559Transaction extends baseTransaction_1.BaseTransaction {
    /**
     * This constructor takes the values, validates them, assigns them and freezes the object.
     *
     * It is not recommended to use this constructor directly. Instead use
     * the static factory methods to assist in creating a Transaction object from
     * varying data types.
     */
    constructor(txData, opts = {}) {
        super({ ...txData, type: TRANSACTION_TYPE }, opts);
        /**
         * The default HF if the tx type is active on that HF
         * or the first greater HF where the tx is active.
         *
         * @hidden
         */
        this.DEFAULT_HARDFORK = 'london';
        const { chainId, accessList, maxFeePerGas, maxPriorityFeePerGas } = txData;
        this.common = this._getCommon(opts.common, chainId);
        this.chainId = this.common.chainId();
        if (this.common.isActivatedEIP(1559) === false) {
            throw new Error('EIP-1559 not enabled on Common');
        }
        this.activeCapabilities = this.activeCapabilities.concat([1559, 2718, 2930]);
        // Populate the access list fields
        const accessListData = util_2.AccessLists.getAccessListData(accessList ?? []);
        this.accessList = accessListData.accessList;
        this.AccessListJSON = accessListData.AccessListJSON;
        // Verify the access list format.
        util_2.AccessLists.verifyAccessList(this.accessList);
        this.maxFeePerGas = (0, util_1.bufferToBigInt)((0, util_1.toBuffer)(maxFeePerGas === '' ? '0x' : maxFeePerGas));
        this.maxPriorityFeePerGas = (0, util_1.bufferToBigInt)((0, util_1.toBuffer)(maxPriorityFeePerGas === '' ? '0x' : maxPriorityFeePerGas));
        this._validateCannotExceedMaxInteger({
            maxFeePerGas: this.maxFeePerGas,
            maxPriorityFeePerGas: this.maxPriorityFeePerGas,
        });
        if (this.gasLimit * this.maxFeePerGas > util_1.MAX_INTEGER) {
            const msg = this._errorMsg('gasLimit * maxFeePerGas cannot exceed MAX_INTEGER (2^256-1)');
            throw new Error(msg);
        }
        if (this.maxFeePerGas < this.maxPriorityFeePerGas) {
            const msg = this._errorMsg('maxFeePerGas cannot be less than maxPriorityFeePerGas (The total must be the larger of the two)');
            throw new Error(msg);
        }
        this._validateYParity();
        this._validateHighS();
        if (this.common.isActivatedEIP(3860)) {
            (0, util_2.checkMaxInitCodeSize)(this.common, this.data.length);
        }
        const freeze = opts?.freeze ?? true;
        if (freeze) {
            Object.freeze(this);
        }
    }
    /**
     * Instantiate a transaction from a data dictionary.
     *
     * Format: { chainId, nonce, maxPriorityFeePerGas, maxFeePerGas, gasLimit, to, value, data,
     * accessList, v, r, s }
     *
     * Notes:
     * - `chainId` will be set automatically if not provided
     * - All parameters are optional and have some basic default values
     */
    static fromTxData(txData, opts = {}) {
        return new FeeMarketEIP1559Transaction(txData, opts);
    }
    /**
     * Instantiate a transaction from the serialized tx.
     *
     * Format: `0x02 || rlp([chainId, nonce, maxPriorityFeePerGas, maxFeePerGas, gasLimit, to, value, data,
     * accessList, signatureYParity, signatureR, signatureS])`
     */
    static fromSerializedTx(serialized, opts = {}) {
        if (!serialized.slice(0, 1).equals(TRANSACTION_TYPE_BUFFER)) {
            throw new Error(`Invalid serialized tx input: not an EIP-1559 transaction (wrong tx type, expected: ${TRANSACTION_TYPE}, received: ${serialized
                .slice(0, 1)
                .toString('hex')}`);
        }
        const values = (0, util_1.arrToBufArr)(rlp_1.RLP.decode(serialized.slice(1)));
        if (!Array.isArray(values)) {
            throw new Error('Invalid serialized tx input: must be array');
        }
        return FeeMarketEIP1559Transaction.fromValuesArray(values, opts);
    }
    /**
     * Create a transaction from a values array.
     *
     * Format: `[chainId, nonce, maxPriorityFeePerGas, maxFeePerGas, gasLimit, to, value, data,
     * accessList, signatureYParity, signatureR, signatureS]`
     */
    static fromValuesArray(values, opts = {}) {
        if (values.length !== 9 && values.length !== 12) {
            throw new Error('Invalid EIP-1559 transaction. Only expecting 9 values (for unsigned tx) or 12 values (for signed tx).');
        }
        const [chainId, nonce, maxPriorityFeePerGas, maxFeePerGas, gasLimit, to, value, data, accessList, v, r, s,] = values;
        (0, util_1.validateNoLeadingZeroes)({ nonce, maxPriorityFeePerGas, maxFeePerGas, gasLimit, value, v, r, s });
        return new FeeMarketEIP1559Transaction({
            chainId: (0, util_1.bufferToBigInt)(chainId),
            nonce,
            maxPriorityFeePerGas,
            maxFeePerGas,
            gasLimit,
            to,
            value,
            data,
            accessList: accessList ?? [],
            v: v !== undefined ? (0, util_1.bufferToBigInt)(v) : undefined,
            r,
            s,
        }, opts);
    }
    /**
     * The amount of gas paid for the data in this tx
     */
    getDataFee() {
        if (this.cache.dataFee && this.cache.dataFee.hardfork === this.common.hardfork()) {
            return this.cache.dataFee.value;
        }
        let cost = super.getDataFee();
        cost += BigInt(util_2.AccessLists.getDataFeeEIP2930(this.accessList, this.common));
        if (Object.isFrozen(this)) {
            this.cache.dataFee = {
                value: cost,
                hardfork: this.common.hardfork(),
            };
        }
        return cost;
    }
    /**
     * The up front amount that an account must have for this transaction to be valid
     * @param baseFee The base fee of the block (will be set to 0 if not provided)
     */
    getUpfrontCost(baseFee = BigInt(0)) {
        const prio = this.maxPriorityFeePerGas;
        const maxBase = this.maxFeePerGas - baseFee;
        const inclusionFeePerGas = prio < maxBase ? prio : maxBase;
        const gasPrice = inclusionFeePerGas + baseFee;
        return this.gasLimit * gasPrice + this.value;
    }
    /**
     * Returns a Buffer Array of the raw Buffers of the EIP-1559 transaction, in order.
     *
     * Format: `[chainId, nonce, maxPriorityFeePerGas, maxFeePerGas, gasLimit, to, value, data,
     * accessList, signatureYParity, signatureR, signatureS]`
     *
     * Use {@link FeeMarketEIP1559Transaction.serialize} to add a transaction to a block
     * with {@link Block.fromValuesArray}.
     *
     * For an unsigned tx this method uses the empty Buffer values for the
     * signature parameters `v`, `r` and `s` for encoding. For an EIP-155 compliant
     * representation for external signing use {@link FeeMarketEIP1559Transaction.getMessageToSign}.
     */
    raw() {
        return [
            (0, util_1.bigIntToUnpaddedBuffer)(this.chainId),
            (0, util_1.bigIntToUnpaddedBuffer)(this.nonce),
            (0, util_1.bigIntToUnpaddedBuffer)(this.maxPriorityFeePerGas),
            (0, util_1.bigIntToUnpaddedBuffer)(this.maxFeePerGas),
            (0, util_1.bigIntToUnpaddedBuffer)(this.gasLimit),
            this.to !== undefined ? this.to.buf : Buffer.from([]),
            (0, util_1.bigIntToUnpaddedBuffer)(this.value),
            this.data,
            this.accessList,
            this.v !== undefined ? (0, util_1.bigIntToUnpaddedBuffer)(this.v) : Buffer.from([]),
            this.r !== undefined ? (0, util_1.bigIntToUnpaddedBuffer)(this.r) : Buffer.from([]),
            this.s !== undefined ? (0, util_1.bigIntToUnpaddedBuffer)(this.s) : Buffer.from([]),
        ];
    }
    /**
     * Returns the serialized encoding of the EIP-1559 transaction.
     *
     * Format: `0x02 || rlp([chainId, nonce, maxPriorityFeePerGas, maxFeePerGas, gasLimit, to, value, data,
     * accessList, signatureYParity, signatureR, signatureS])`
     *
     * Note that in contrast to the legacy tx serialization format this is not
     * valid RLP any more due to the raw tx type preceding and concatenated to
     * the RLP encoding of the values.
     */
    serialize() {
        const base = this.raw();
        return Buffer.concat([
            TRANSACTION_TYPE_BUFFER,
            Buffer.from(rlp_1.RLP.encode((0, util_1.bufArrToArr)(base))),
        ]);
    }
    /**
     * Returns the serialized unsigned tx (hashed or raw), which can be used
     * to sign the transaction (e.g. for sending to a hardware wallet).
     *
     * Note: in contrast to the legacy tx the raw message format is already
     * serialized and doesn't need to be RLP encoded any more.
     *
     * ```javascript
     * const serializedMessage = tx.getMessageToSign(false) // use this for the HW wallet input
     * ```
     *
     * @param hashMessage - Return hashed message if set to true (default: true)
     */
    getMessageToSign(hashMessage = true) {
        const base = this.raw().slice(0, 9);
        const message = Buffer.concat([
            TRANSACTION_TYPE_BUFFER,
            Buffer.from(rlp_1.RLP.encode((0, util_1.bufArrToArr)(base))),
        ]);
        if (hashMessage) {
            return Buffer.from((0, keccak_1.keccak256)(message));
        }
        else {
            return message;
        }
    }
    /**
     * Computes a sha3-256 hash of the serialized tx.
     *
     * This method can only be used for signed txs (it throws otherwise).
     * Use {@link FeeMarketEIP1559Transaction.getMessageToSign} to get a tx hash for the purpose of signing.
     */
    hash() {
        if (!this.isSigned()) {
            const msg = this._errorMsg('Cannot call hash method if transaction is not signed');
            throw new Error(msg);
        }
        if (Object.isFrozen(this)) {
            if (!this.cache.hash) {
                this.cache.hash = Buffer.from((0, keccak_1.keccak256)(this.serialize()));
            }
            return this.cache.hash;
        }
        return Buffer.from((0, keccak_1.keccak256)(this.serialize()));
    }
    /**
     * Computes a sha3-256 hash which can be used to verify the signature
     */
    getMessageToVerifySignature() {
        return this.getMessageToSign();
    }
    /**
     * Returns the public key of the sender
     */
    getSenderPublicKey() {
        if (!this.isSigned()) {
            const msg = this._errorMsg('Cannot call this method if transaction is not signed');
            throw new Error(msg);
        }
        const msgHash = this.getMessageToVerifySignature();
        const { v, r, s } = this;
        this._validateHighS();
        try {
            return (0, util_1.ecrecover)(msgHash, v + BigInt(27), // Recover the 27 which was stripped from ecsign
            (0, util_1.bigIntToUnpaddedBuffer)(r), (0, util_1.bigIntToUnpaddedBuffer)(s));
        }
        catch (e) {
            const msg = this._errorMsg('Invalid Signature');
            throw new Error(msg);
        }
    }
    _processSignature(v, r, s) {
        const opts = { ...this.txOptions, common: this.common };
        return FeeMarketEIP1559Transaction.fromTxData({
            chainId: this.chainId,
            nonce: this.nonce,
            maxPriorityFeePerGas: this.maxPriorityFeePerGas,
            maxFeePerGas: this.maxFeePerGas,
            gasLimit: this.gasLimit,
            to: this.to,
            value: this.value,
            data: this.data,
            accessList: this.accessList,
            v: v - BigInt(27),
            r: (0, util_1.bufferToBigInt)(r),
            s: (0, util_1.bufferToBigInt)(s),
        }, opts);
    }
    /**
     * Returns an object with the JSON representation of the transaction
     */
    toJSON() {
        const accessListJSON = util_2.AccessLists.getAccessListJSON(this.accessList);
        return {
            chainId: (0, util_1.bigIntToHex)(this.chainId),
            nonce: (0, util_1.bigIntToHex)(this.nonce),
            maxPriorityFeePerGas: (0, util_1.bigIntToHex)(this.maxPriorityFeePerGas),
            maxFeePerGas: (0, util_1.bigIntToHex)(this.maxFeePerGas),
            gasLimit: (0, util_1.bigIntToHex)(this.gasLimit),
            to: this.to !== undefined ? this.to.toString() : undefined,
            value: (0, util_1.bigIntToHex)(this.value),
            data: '0x' + this.data.toString('hex'),
            accessList: accessListJSON,
            v: this.v !== undefined ? (0, util_1.bigIntToHex)(this.v) : undefined,
            r: this.r !== undefined ? (0, util_1.bigIntToHex)(this.r) : undefined,
            s: this.s !== undefined ? (0, util_1.bigIntToHex)(this.s) : undefined,
        };
    }
    /**
     * Return a compact error string representation of the object
     */
    errorStr() {
        let errorStr = this._getSharedErrorPostfix();
        errorStr += ` maxFeePerGas=${this.maxFeePerGas} maxPriorityFeePerGas=${this.maxPriorityFeePerGas}`;
        return errorStr;
    }
    /**
     * Internal helper function to create an annotated error message
     *
     * @param msg Base error message
     * @hidden
     */
    _errorMsg(msg) {
        return `${msg} (${this.errorStr()})`;
    }
}
exports.FeeMarketEIP1559Transaction = FeeMarketEIP1559Transaction;

}).call(this)}).call(this,require("buffer").Buffer)
},{"./baseTransaction":2,"./util":9,"@ethereumjs/rlp":1,"@ethereumjs/util":68,"buffer":89,"ethereum-cryptography/keccak":61}],4:[function(require,module,exports){
(function (Buffer){(function (){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.AccessListEIP2930Transaction = void 0;
const rlp_1 = require("@ethereumjs/rlp");
const util_1 = require("@ethereumjs/util");
const keccak_1 = require("ethereum-cryptography/keccak");
const baseTransaction_1 = require("./baseTransaction");
const util_2 = require("./util");
const TRANSACTION_TYPE = 1;
const TRANSACTION_TYPE_BUFFER = Buffer.from(TRANSACTION_TYPE.toString(16).padStart(2, '0'), 'hex');
/**
 * Typed transaction with optional access lists
 *
 * - TransactionType: 1
 * - EIP: [EIP-2930](https://eips.ethereum.org/EIPS/eip-2930)
 */
class AccessListEIP2930Transaction extends baseTransaction_1.BaseTransaction {
    /**
     * This constructor takes the values, validates them, assigns them and freezes the object.
     *
     * It is not recommended to use this constructor directly. Instead use
     * the static factory methods to assist in creating a Transaction object from
     * varying data types.
     */
    constructor(txData, opts = {}) {
        super({ ...txData, type: TRANSACTION_TYPE }, opts);
        /**
         * The default HF if the tx type is active on that HF
         * or the first greater HF where the tx is active.
         *
         * @hidden
         */
        this.DEFAULT_HARDFORK = 'berlin';
        const { chainId, accessList, gasPrice } = txData;
        this.common = this._getCommon(opts.common, chainId);
        this.chainId = this.common.chainId();
        // EIP-2718 check is done in Common
        if (!this.common.isActivatedEIP(2930)) {
            throw new Error('EIP-2930 not enabled on Common');
        }
        this.activeCapabilities = this.activeCapabilities.concat([2718, 2930]);
        // Populate the access list fields
        const accessListData = util_2.AccessLists.getAccessListData(accessList ?? []);
        this.accessList = accessListData.accessList;
        this.AccessListJSON = accessListData.AccessListJSON;
        // Verify the access list format.
        util_2.AccessLists.verifyAccessList(this.accessList);
        this.gasPrice = (0, util_1.bufferToBigInt)((0, util_1.toBuffer)(gasPrice === '' ? '0x' : gasPrice));
        this._validateCannotExceedMaxInteger({
            gasPrice: this.gasPrice,
        });
        if (this.gasPrice * this.gasLimit > util_1.MAX_INTEGER) {
            const msg = this._errorMsg('gasLimit * gasPrice cannot exceed MAX_INTEGER');
            throw new Error(msg);
        }
        this._validateYParity();
        this._validateHighS();
        if (this.common.isActivatedEIP(3860)) {
            (0, util_2.checkMaxInitCodeSize)(this.common, this.data.length);
        }
        const freeze = opts?.freeze ?? true;
        if (freeze) {
            Object.freeze(this);
        }
    }
    /**
     * Instantiate a transaction from a data dictionary.
     *
     * Format: { chainId, nonce, gasPrice, gasLimit, to, value, data, accessList,
     * v, r, s }
     *
     * Notes:
     * - `chainId` will be set automatically if not provided
     * - All parameters are optional and have some basic default values
     */
    static fromTxData(txData, opts = {}) {
        return new AccessListEIP2930Transaction(txData, opts);
    }
    /**
     * Instantiate a transaction from the serialized tx.
     *
     * Format: `0x01 || rlp([chainId, nonce, gasPrice, gasLimit, to, value, data, accessList,
     * signatureYParity (v), signatureR (r), signatureS (s)])`
     */
    static fromSerializedTx(serialized, opts = {}) {
        if (!serialized.slice(0, 1).equals(TRANSACTION_TYPE_BUFFER)) {
            throw new Error(`Invalid serialized tx input: not an EIP-2930 transaction (wrong tx type, expected: ${TRANSACTION_TYPE}, received: ${serialized
                .slice(0, 1)
                .toString('hex')}`);
        }
        const values = (0, util_1.arrToBufArr)(rlp_1.RLP.decode(Uint8Array.from(serialized.slice(1))));
        if (!Array.isArray(values)) {
            throw new Error('Invalid serialized tx input: must be array');
        }
        return AccessListEIP2930Transaction.fromValuesArray(values, opts);
    }
    /**
     * Create a transaction from a values array.
     *
     * Format: `[chainId, nonce, gasPrice, gasLimit, to, value, data, accessList,
     * signatureYParity (v), signatureR (r), signatureS (s)]`
     */
    static fromValuesArray(values, opts = {}) {
        if (values.length !== 8 && values.length !== 11) {
            throw new Error('Invalid EIP-2930 transaction. Only expecting 8 values (for unsigned tx) or 11 values (for signed tx).');
        }
        const [chainId, nonce, gasPrice, gasLimit, to, value, data, accessList, v, r, s] = values;
        (0, util_1.validateNoLeadingZeroes)({ nonce, gasPrice, gasLimit, value, v, r, s });
        const emptyAccessList = [];
        return new AccessListEIP2930Transaction({
            chainId: (0, util_1.bufferToBigInt)(chainId),
            nonce,
            gasPrice,
            gasLimit,
            to,
            value,
            data,
            accessList: accessList ?? emptyAccessList,
            v: v !== undefined ? (0, util_1.bufferToBigInt)(v) : undefined,
            r,
            s,
        }, opts);
    }
    /**
     * The amount of gas paid for the data in this tx
     */
    getDataFee() {
        if (this.cache.dataFee && this.cache.dataFee.hardfork === this.common.hardfork()) {
            return this.cache.dataFee.value;
        }
        let cost = super.getDataFee();
        cost += BigInt(util_2.AccessLists.getDataFeeEIP2930(this.accessList, this.common));
        if (Object.isFrozen(this)) {
            this.cache.dataFee = {
                value: cost,
                hardfork: this.common.hardfork(),
            };
        }
        return cost;
    }
    /**
     * The up front amount that an account must have for this transaction to be valid
     */
    getUpfrontCost() {
        return this.gasLimit * this.gasPrice + this.value;
    }
    /**
     * Returns a Buffer Array of the raw Buffers of the EIP-2930 transaction, in order.
     *
     * Format: `[chainId, nonce, gasPrice, gasLimit, to, value, data, accessList,
     * signatureYParity (v), signatureR (r), signatureS (s)]`
     *
     * Use {@link AccessListEIP2930Transaction.serialize} to add a transaction to a block
     * with {@link Block.fromValuesArray}.
     *
     * For an unsigned tx this method uses the empty Buffer values for the
     * signature parameters `v`, `r` and `s` for encoding. For an EIP-155 compliant
     * representation for external signing use {@link AccessListEIP2930Transaction.getMessageToSign}.
     */
    raw() {
        return [
            (0, util_1.bigIntToUnpaddedBuffer)(this.chainId),
            (0, util_1.bigIntToUnpaddedBuffer)(this.nonce),
            (0, util_1.bigIntToUnpaddedBuffer)(this.gasPrice),
            (0, util_1.bigIntToUnpaddedBuffer)(this.gasLimit),
            this.to !== undefined ? this.to.buf : Buffer.from([]),
            (0, util_1.bigIntToUnpaddedBuffer)(this.value),
            this.data,
            this.accessList,
            this.v !== undefined ? (0, util_1.bigIntToUnpaddedBuffer)(this.v) : Buffer.from([]),
            this.r !== undefined ? (0, util_1.bigIntToUnpaddedBuffer)(this.r) : Buffer.from([]),
            this.s !== undefined ? (0, util_1.bigIntToUnpaddedBuffer)(this.s) : Buffer.from([]),
        ];
    }
    /**
     * Returns the serialized encoding of the EIP-2930 transaction.
     *
     * Format: `0x01 || rlp([chainId, nonce, gasPrice, gasLimit, to, value, data, accessList,
     * signatureYParity (v), signatureR (r), signatureS (s)])`
     *
     * Note that in contrast to the legacy tx serialization format this is not
     * valid RLP any more due to the raw tx type preceding and concatenated to
     * the RLP encoding of the values.
     */
    serialize() {
        const base = this.raw();
        return Buffer.concat([
            TRANSACTION_TYPE_BUFFER,
            Buffer.from(rlp_1.RLP.encode((0, util_1.bufArrToArr)(base))),
        ]);
    }
    /**
     * Returns the serialized unsigned tx (hashed or raw), which can be used
     * to sign the transaction (e.g. for sending to a hardware wallet).
     *
     * Note: in contrast to the legacy tx the raw message format is already
     * serialized and doesn't need to be RLP encoded any more.
     *
     * ```javascript
     * const serializedMessage = tx.getMessageToSign(false) // use this for the HW wallet input
     * ```
     *
     * @param hashMessage - Return hashed message if set to true (default: true)
     */
    getMessageToSign(hashMessage = true) {
        const base = this.raw().slice(0, 8);
        const message = Buffer.concat([
            TRANSACTION_TYPE_BUFFER,
            Buffer.from(rlp_1.RLP.encode((0, util_1.bufArrToArr)(base))),
        ]);
        if (hashMessage) {
            return Buffer.from((0, keccak_1.keccak256)(message));
        }
        else {
            return message;
        }
    }
    /**
     * Computes a sha3-256 hash of the serialized tx.
     *
     * This method can only be used for signed txs (it throws otherwise).
     * Use {@link AccessListEIP2930Transaction.getMessageToSign} to get a tx hash for the purpose of signing.
     */
    hash() {
        if (!this.isSigned()) {
            const msg = this._errorMsg('Cannot call hash method if transaction is not signed');
            throw new Error(msg);
        }
        if (Object.isFrozen(this)) {
            if (!this.cache.hash) {
                this.cache.hash = Buffer.from((0, keccak_1.keccak256)(this.serialize()));
            }
            return this.cache.hash;
        }
        return Buffer.from((0, keccak_1.keccak256)(this.serialize()));
    }
    /**
     * Computes a sha3-256 hash which can be used to verify the signature
     */
    getMessageToVerifySignature() {
        return this.getMessageToSign();
    }
    /**
     * Returns the public key of the sender
     */
    getSenderPublicKey() {
        if (!this.isSigned()) {
            const msg = this._errorMsg('Cannot call this method if transaction is not signed');
            throw new Error(msg);
        }
        const msgHash = this.getMessageToVerifySignature();
        const { v, r, s } = this;
        this._validateHighS();
        try {
            return (0, util_1.ecrecover)(msgHash, v + BigInt(27), // Recover the 27 which was stripped from ecsign
            (0, util_1.bigIntToUnpaddedBuffer)(r), (0, util_1.bigIntToUnpaddedBuffer)(s));
        }
        catch (e) {
            const msg = this._errorMsg('Invalid Signature');
            throw new Error(msg);
        }
    }
    _processSignature(v, r, s) {
        const opts = { ...this.txOptions, common: this.common };
        return AccessListEIP2930Transaction.fromTxData({
            chainId: this.chainId,
            nonce: this.nonce,
            gasPrice: this.gasPrice,
            gasLimit: this.gasLimit,
            to: this.to,
            value: this.value,
            data: this.data,
            accessList: this.accessList,
            v: v - BigInt(27),
            r: (0, util_1.bufferToBigInt)(r),
            s: (0, util_1.bufferToBigInt)(s),
        }, opts);
    }
    /**
     * Returns an object with the JSON representation of the transaction
     */
    toJSON() {
        const accessListJSON = util_2.AccessLists.getAccessListJSON(this.accessList);
        return {
            chainId: (0, util_1.bigIntToHex)(this.chainId),
            nonce: (0, util_1.bigIntToHex)(this.nonce),
            gasPrice: (0, util_1.bigIntToHex)(this.gasPrice),
            gasLimit: (0, util_1.bigIntToHex)(this.gasLimit),
            to: this.to !== undefined ? this.to.toString() : undefined,
            value: (0, util_1.bigIntToHex)(this.value),
            data: '0x' + this.data.toString('hex'),
            accessList: accessListJSON,
            v: this.v !== undefined ? (0, util_1.bigIntToHex)(this.v) : undefined,
            r: this.r !== undefined ? (0, util_1.bigIntToHex)(this.r) : undefined,
            s: this.s !== undefined ? (0, util_1.bigIntToHex)(this.s) : undefined,
        };
    }
    /**
     * Return a compact error string representation of the object
     */
    errorStr() {
        let errorStr = this._getSharedErrorPostfix();
        // Keep ? for this.accessList since this otherwise causes Hardhat E2E tests to fail
        errorStr += ` gasPrice=${this.gasPrice} accessListCount=${this.accessList?.length ?? 0}`;
        return errorStr;
    }
    /**
     * Internal helper function to create an annotated error message
     *
     * @param msg Base error message
     * @hidden
     */
    _errorMsg(msg) {
        return `${msg} (${this.errorStr()})`;
    }
}
exports.AccessListEIP2930Transaction = AccessListEIP2930Transaction;

}).call(this)}).call(this,require("buffer").Buffer)
},{"./baseTransaction":2,"./util":9,"@ethereumjs/rlp":1,"@ethereumjs/util":68,"buffer":89,"ethereum-cryptography/keccak":61}],5:[function(require,module,exports){
"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __exportStar = (this && this.__exportStar) || function(m, exports) {
    for (var p in m) if (p !== "default" && !Object.prototype.hasOwnProperty.call(exports, p)) __createBinding(exports, m, p);
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.TransactionFactory = exports.Transaction = exports.AccessListEIP2930Transaction = exports.FeeMarketEIP1559Transaction = void 0;
var eip1559Transaction_1 = require("./eip1559Transaction");
Object.defineProperty(exports, "FeeMarketEIP1559Transaction", { enumerable: true, get: function () { return eip1559Transaction_1.FeeMarketEIP1559Transaction; } });
var eip2930Transaction_1 = require("./eip2930Transaction");
Object.defineProperty(exports, "AccessListEIP2930Transaction", { enumerable: true, get: function () { return eip2930Transaction_1.AccessListEIP2930Transaction; } });
var legacyTransaction_1 = require("./legacyTransaction");
Object.defineProperty(exports, "Transaction", { enumerable: true, get: function () { return legacyTransaction_1.Transaction; } });
var transactionFactory_1 = require("./transactionFactory");
Object.defineProperty(exports, "TransactionFactory", { enumerable: true, get: function () { return transactionFactory_1.TransactionFactory; } });
__exportStar(require("./types"), exports);

},{"./eip1559Transaction":3,"./eip2930Transaction":4,"./legacyTransaction":6,"./transactionFactory":7,"./types":8}],6:[function(require,module,exports){
(function (Buffer){(function (){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Transaction = void 0;
const rlp_1 = require("@ethereumjs/rlp");
const util_1 = require("@ethereumjs/util");
const keccak_1 = require("ethereum-cryptography/keccak");
const baseTransaction_1 = require("./baseTransaction");
const types_1 = require("./types");
const util_2 = require("./util");
const TRANSACTION_TYPE = 0;
function meetsEIP155(_v, chainId) {
    const v = Number(_v);
    const chainIdDoubled = Number(chainId) * 2;
    return v === chainIdDoubled + 35 || v === chainIdDoubled + 36;
}
/**
 * An Ethereum non-typed (legacy) transaction
 */
class Transaction extends baseTransaction_1.BaseTransaction {
    /**
     * This constructor takes the values, validates them, assigns them and freezes the object.
     *
     * It is not recommended to use this constructor directly. Instead use
     * the static factory methods to assist in creating a Transaction object from
     * varying data types.
     */
    constructor(txData, opts = {}) {
        super({ ...txData, type: TRANSACTION_TYPE }, opts);
        this.common = this._validateTxV(this.v, opts.common);
        this.gasPrice = (0, util_1.bufferToBigInt)((0, util_1.toBuffer)(txData.gasPrice === '' ? '0x' : txData.gasPrice));
        if (this.gasPrice * this.gasLimit > util_1.MAX_INTEGER) {
            const msg = this._errorMsg('gas limit * gasPrice cannot exceed MAX_INTEGER (2^256-1)');
            throw new Error(msg);
        }
        this._validateCannotExceedMaxInteger({ gasPrice: this.gasPrice });
        if (this.common.gteHardfork('spuriousDragon')) {
            if (!this.isSigned()) {
                this.activeCapabilities.push(types_1.Capability.EIP155ReplayProtection);
            }
            else {
                // EIP155 spec:
                // If block.number >= 2,675,000 and v = CHAIN_ID * 2 + 35 or v = CHAIN_ID * 2 + 36
                // then when computing the hash of a transaction for purposes of signing or recovering
                // instead of hashing only the first six elements (i.e. nonce, gasprice, startgas, to, value, data)
                // hash nine elements, with v replaced by CHAIN_ID, r = 0 and s = 0.
                // v and chain ID meet EIP-155 conditions
                if (meetsEIP155(this.v, this.common.chainId())) {
                    this.activeCapabilities.push(types_1.Capability.EIP155ReplayProtection);
                }
            }
        }
        if (this.common.isActivatedEIP(3860)) {
            (0, util_2.checkMaxInitCodeSize)(this.common, this.data.length);
        }
        const freeze = opts?.freeze ?? true;
        if (freeze) {
            Object.freeze(this);
        }
    }
    /**
     * Instantiate a transaction from a data dictionary.
     *
     * Format: { nonce, gasPrice, gasLimit, to, value, data, v, r, s }
     *
     * Notes:
     * - All parameters are optional and have some basic default values
     */
    static fromTxData(txData, opts = {}) {
        return new Transaction(txData, opts);
    }
    /**
     * Instantiate a transaction from the serialized tx.
     *
     * Format: `rlp([nonce, gasPrice, gasLimit, to, value, data, v, r, s])`
     */
    static fromSerializedTx(serialized, opts = {}) {
        const values = (0, util_1.arrToBufArr)(rlp_1.RLP.decode(Uint8Array.from(serialized)));
        if (!Array.isArray(values)) {
            throw new Error('Invalid serialized tx input. Must be array');
        }
        return this.fromValuesArray(values, opts);
    }
    /**
     * Create a transaction from a values array.
     *
     * Format: `[nonce, gasPrice, gasLimit, to, value, data, v, r, s]`
     */
    static fromValuesArray(values, opts = {}) {
        // If length is not 6, it has length 9. If v/r/s are empty Buffers, it is still an unsigned transaction
        // This happens if you get the RLP data from `raw()`
        if (values.length !== 6 && values.length !== 9) {
            throw new Error('Invalid transaction. Only expecting 6 values (for unsigned tx) or 9 values (for signed tx).');
        }
        const [nonce, gasPrice, gasLimit, to, value, data, v, r, s] = values;
        (0, util_1.validateNoLeadingZeroes)({ nonce, gasPrice, gasLimit, value, v, r, s });
        return new Transaction({
            nonce,
            gasPrice,
            gasLimit,
            to,
            value,
            data,
            v,
            r,
            s,
        }, opts);
    }
    /**
     * Returns a Buffer Array of the raw Buffers of the legacy transaction, in order.
     *
     * Format: `[nonce, gasPrice, gasLimit, to, value, data, v, r, s]`
     *
     * For legacy txs this is also the correct format to add transactions
     * to a block with {@link Block.fromValuesArray} (use the `serialize()` method
     * for typed txs).
     *
     * For an unsigned tx this method returns the empty Buffer values
     * for the signature parameters `v`, `r` and `s`. For an EIP-155 compliant
     * representation have a look at {@link Transaction.getMessageToSign}.
     */
    raw() {
        return [
            (0, util_1.bigIntToUnpaddedBuffer)(this.nonce),
            (0, util_1.bigIntToUnpaddedBuffer)(this.gasPrice),
            (0, util_1.bigIntToUnpaddedBuffer)(this.gasLimit),
            this.to !== undefined ? this.to.buf : Buffer.from([]),
            (0, util_1.bigIntToUnpaddedBuffer)(this.value),
            this.data,
            this.v !== undefined ? (0, util_1.bigIntToUnpaddedBuffer)(this.v) : Buffer.from([]),
            this.r !== undefined ? (0, util_1.bigIntToUnpaddedBuffer)(this.r) : Buffer.from([]),
            this.s !== undefined ? (0, util_1.bigIntToUnpaddedBuffer)(this.s) : Buffer.from([]),
        ];
    }
    /**
     * Returns the serialized encoding of the legacy transaction.
     *
     * Format: `rlp([nonce, gasPrice, gasLimit, to, value, data, v, r, s])`
     *
     * For an unsigned tx this method uses the empty Buffer values for the
     * signature parameters `v`, `r` and `s` for encoding. For an EIP-155 compliant
     * representation for external signing use {@link Transaction.getMessageToSign}.
     */
    serialize() {
        return Buffer.from(rlp_1.RLP.encode((0, util_1.bufArrToArr)(this.raw())));
    }
    _getMessageToSign() {
        const values = [
            (0, util_1.bigIntToUnpaddedBuffer)(this.nonce),
            (0, util_1.bigIntToUnpaddedBuffer)(this.gasPrice),
            (0, util_1.bigIntToUnpaddedBuffer)(this.gasLimit),
            this.to !== undefined ? this.to.buf : Buffer.from([]),
            (0, util_1.bigIntToUnpaddedBuffer)(this.value),
            this.data,
        ];
        if (this.supports(types_1.Capability.EIP155ReplayProtection)) {
            values.push((0, util_1.toBuffer)(this.common.chainId()));
            values.push((0, util_1.unpadBuffer)((0, util_1.toBuffer)(0)));
            values.push((0, util_1.unpadBuffer)((0, util_1.toBuffer)(0)));
        }
        return values;
    }
    getMessageToSign(hashMessage = true) {
        const message = this._getMessageToSign();
        if (hashMessage) {
            return Buffer.from((0, keccak_1.keccak256)(rlp_1.RLP.encode((0, util_1.bufArrToArr)(message))));
        }
        else {
            return message;
        }
    }
    /**
     * The amount of gas paid for the data in this tx
     */
    getDataFee() {
        if (this.cache.dataFee && this.cache.dataFee.hardfork === this.common.hardfork()) {
            return this.cache.dataFee.value;
        }
        if (Object.isFrozen(this)) {
            this.cache.dataFee = {
                value: super.getDataFee(),
                hardfork: this.common.hardfork(),
            };
        }
        return super.getDataFee();
    }
    /**
     * The up front amount that an account must have for this transaction to be valid
     */
    getUpfrontCost() {
        return this.gasLimit * this.gasPrice + this.value;
    }
    /**
     * Computes a sha3-256 hash of the serialized tx.
     *
     * This method can only be used for signed txs (it throws otherwise).
     * Use {@link Transaction.getMessageToSign} to get a tx hash for the purpose of signing.
     */
    hash() {
        if (!this.isSigned()) {
            const msg = this._errorMsg('Cannot call hash method if transaction is not signed');
            throw new Error(msg);
        }
        if (Object.isFrozen(this)) {
            if (!this.cache.hash) {
                this.cache.hash = Buffer.from((0, keccak_1.keccak256)(rlp_1.RLP.encode((0, util_1.bufArrToArr)(this.raw()))));
            }
            return this.cache.hash;
        }
        return Buffer.from((0, keccak_1.keccak256)(rlp_1.RLP.encode((0, util_1.bufArrToArr)(this.raw()))));
    }
    /**
     * Computes a sha3-256 hash which can be used to verify the signature
     */
    getMessageToVerifySignature() {
        if (!this.isSigned()) {
            const msg = this._errorMsg('This transaction is not signed');
            throw new Error(msg);
        }
        const message = this._getMessageToSign();
        return Buffer.from((0, keccak_1.keccak256)(rlp_1.RLP.encode((0, util_1.bufArrToArr)(message))));
    }
    /**
     * Returns the public key of the sender
     */
    getSenderPublicKey() {
        const msgHash = this.getMessageToVerifySignature();
        const { v, r, s } = this;
        this._validateHighS();
        try {
            return (0, util_1.ecrecover)(msgHash, v, (0, util_1.bigIntToUnpaddedBuffer)(r), (0, util_1.bigIntToUnpaddedBuffer)(s), this.supports(types_1.Capability.EIP155ReplayProtection) ? this.common.chainId() : undefined);
        }
        catch (e) {
            const msg = this._errorMsg('Invalid Signature');
            throw new Error(msg);
        }
    }
    /**
     * Process the v, r, s values from the `sign` method of the base transaction.
     */
    _processSignature(v, r, s) {
        if (this.supports(types_1.Capability.EIP155ReplayProtection)) {
            v += this.common.chainId() * BigInt(2) + BigInt(8);
        }
        const opts = { ...this.txOptions, common: this.common };
        return Transaction.fromTxData({
            nonce: this.nonce,
            gasPrice: this.gasPrice,
            gasLimit: this.gasLimit,
            to: this.to,
            value: this.value,
            data: this.data,
            v,
            r: (0, util_1.bufferToBigInt)(r),
            s: (0, util_1.bufferToBigInt)(s),
        }, opts);
    }
    /**
     * Returns an object with the JSON representation of the transaction.
     */
    toJSON() {
        return {
            nonce: (0, util_1.bigIntToHex)(this.nonce),
            gasPrice: (0, util_1.bigIntToHex)(this.gasPrice),
            gasLimit: (0, util_1.bigIntToHex)(this.gasLimit),
            to: this.to !== undefined ? this.to.toString() : undefined,
            value: (0, util_1.bigIntToHex)(this.value),
            data: '0x' + this.data.toString('hex'),
            v: this.v !== undefined ? (0, util_1.bigIntToHex)(this.v) : undefined,
            r: this.r !== undefined ? (0, util_1.bigIntToHex)(this.r) : undefined,
            s: this.s !== undefined ? (0, util_1.bigIntToHex)(this.s) : undefined,
        };
    }
    /**
     * Validates tx's `v` value
     */
    _validateTxV(_v, common) {
        // let chainIdBigInt;
        // const v = _v !== undefined ? Number(_v) : undefined;
        // // Check for valid v values in the scope of a signed legacy tx
        // if (v !== undefined) {
        //     // v is 1. not matching the EIP-155 chainId included case and...
        //     // v is 2. not matching the classic v=27 or v=28 case
        //     if (v < 37 && v !== 27 && v !== 28) {
        //         throw new Error(`Legacy txs need either v = 27/28 or v >= 37 (EIP-155 replay protection), got v = ${v}`);
        //     }
        // }
        // // No unsigned tx and EIP-155 activated and chain ID included
        // if (v !== undefined &&
        //     v !== 0 &&
        //     (!common || common.gteHardfork('spuriousDragon')) &&
        //     v !== 27 &&
        //     v !== 28) {
        //     if (common) {
        //         if (!meetsEIP155(BigInt(v), common.chainId())) {
        //             throw new Error(`Incompatible EIP155-based V ${v} and chain id ${common.chainId()}. See the Common parameter of the Transaction constructor to set the chain id.`);
        //         }
        //     }
        //     else {
        //         // Derive the original chain ID
        //         let numSub;
        //         if ((v - 35) % 2 === 0) {
        //             numSub = 35;
        //         }
        //         else {
        //             numSub = 36;
        //         }
        //         // Use derived chain ID to create a proper Common
        //         chainIdBigInt = BigInt(v - numSub) / BigInt(2);
        //     }
        // }

        return this._getCommon(common, BigInt(`0x${_v}`));
    }

    /**
     * Return a compact error string representation of the object
     */
    errorStr() {
        let errorStr = this._getSharedErrorPostfix();
        errorStr += ` gasPrice=${this.gasPrice}`;
        return errorStr;
    }
    /**
     * Internal helper function to create an annotated error message
     *
     * @param msg Base error message
     * @hidden
     */
    _errorMsg(msg) {
        return `${msg} (${this.errorStr()})`;
    }
}
exports.Transaction = Transaction;

}).call(this)}).call(this,require("buffer").Buffer)
},{"./baseTransaction":2,"./types":8,"./util":9,"@ethereumjs/rlp":1,"@ethereumjs/util":68,"buffer":89,"ethereum-cryptography/keccak":61}],7:[function(require,module,exports){
(function (Buffer){(function (){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.TransactionFactory = void 0;
const util_1 = require("@ethereumjs/util");
const eip1559Transaction_1 = require("./eip1559Transaction");
const eip2930Transaction_1 = require("./eip2930Transaction");
const legacyTransaction_1 = require("./legacyTransaction");
class TransactionFactory {
    // It is not possible to instantiate a TransactionFactory object.
    constructor() { }
    /**
     * Create a transaction from a `txData` object
     *
     * @param txData - The transaction data. The `type` field will determine which transaction type is returned (if undefined, creates a legacy transaction)
     * @param txOptions - Options to pass on to the constructor of the transaction
     */
    static fromTxData(txData, txOptions = {}) {
        if (!('type' in txData) || txData.type === undefined) {
            // Assume legacy transaction
            return legacyTransaction_1.Transaction.fromTxData(txData, txOptions);
        }
        else {
            const txType = Number((0, util_1.bufferToBigInt)((0, util_1.toBuffer)(txData.type)));
            if (txType === 0) {
                return legacyTransaction_1.Transaction.fromTxData(txData, txOptions);
            }
            else if (txType === 1) {
                return eip2930Transaction_1.AccessListEIP2930Transaction.fromTxData(txData, txOptions);
            }
            else if (txType === 2) {
                return eip1559Transaction_1.FeeMarketEIP1559Transaction.fromTxData(txData, txOptions);
            }
            else {
                throw new Error(`Tx instantiation with type ${txType} not supported`);
            }
        }
    }
    /**
     * This method tries to decode serialized data.
     *
     * @param data - The data Buffer
     * @param txOptions - The transaction options
     */
    static fromSerializedData(data, txOptions = {}) {
        if (data[0] <= 0x7f) {
            // Determine the type.
            let EIP;
            switch (data[0]) {
                case 1:
                    EIP = 2930;
                    break;
                case 2:
                    EIP = 1559;
                    break;
                default:
                    throw new Error(`TypedTransaction with ID ${data[0]} unknown`);
            }
            if (EIP === 1559) {
                return eip1559Transaction_1.FeeMarketEIP1559Transaction.fromSerializedTx(data, txOptions);
            }
            else {
                // EIP === 2930
                return eip2930Transaction_1.AccessListEIP2930Transaction.fromSerializedTx(data, txOptions);
            }
        }
        else {
            return legacyTransaction_1.Transaction.fromSerializedTx(data, txOptions);
        }
    }
    /**
     * When decoding a BlockBody, in the transactions field, a field is either:
     * A Buffer (a TypedTransaction - encoded as TransactionType || rlp(TransactionPayload))
     * A Buffer[] (Legacy Transaction)
     * This method returns the right transaction.
     *
     * @param data - A Buffer or Buffer[]
     * @param txOptions - The transaction options
     */
    static fromBlockBodyData(data, txOptions = {}) {
        if (Buffer.isBuffer(data)) {
            return this.fromSerializedData(data, txOptions);
        }
        else if (Array.isArray(data)) {
            // It is a legacy transaction
            return legacyTransaction_1.Transaction.fromValuesArray(data, txOptions);
        }
        else {
            throw new Error('Cannot decode transaction: unknown type input');
        }
    }
}
exports.TransactionFactory = TransactionFactory;

}).call(this)}).call(this,{"isBuffer":require("../../../is-buffer/index.js")})
},{"../../../is-buffer/index.js":85,"./eip1559Transaction":3,"./eip2930Transaction":4,"./legacyTransaction":6,"@ethereumjs/util":68}],8:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.isAccessList = exports.isAccessListBuffer = exports.Capability = void 0;
/**
 * Can be used in conjunction with {@link Transaction.supports}
 * to query on tx capabilities
 */
var Capability;
(function (Capability) {
    /**
     * Tx supports EIP-155 replay protection
     * See: [155](https://eips.ethereum.org/EIPS/eip-155) Replay Attack Protection EIP
     */
    Capability[Capability["EIP155ReplayProtection"] = 155] = "EIP155ReplayProtection";
    /**
     * Tx supports EIP-1559 gas fee market mechanism
     * See: [1559](https://eips.ethereum.org/EIPS/eip-1559) Fee Market EIP
     */
    Capability[Capability["EIP1559FeeMarket"] = 1559] = "EIP1559FeeMarket";
    /**
     * Tx is a typed transaction as defined in EIP-2718
     * See: [2718](https://eips.ethereum.org/EIPS/eip-2718) Transaction Type EIP
     */
    Capability[Capability["EIP2718TypedTransaction"] = 2718] = "EIP2718TypedTransaction";
    /**
     * Tx supports access list generation as defined in EIP-2930
     * See: [2930](https://eips.ethereum.org/EIPS/eip-2930) Access Lists EIP
     */
    Capability[Capability["EIP2930AccessLists"] = 2930] = "EIP2930AccessLists";
})(Capability = exports.Capability || (exports.Capability = {}));
function isAccessListBuffer(input) {
    if (input.length === 0) {
        return true;
    }
    const firstItem = input[0];
    if (Array.isArray(firstItem)) {
        return true;
    }
    return false;
}
exports.isAccessListBuffer = isAccessListBuffer;
function isAccessList(input) {
    return !isAccessListBuffer(input); // This is exactly the same method, except the output is negated.
}
exports.isAccessList = isAccessList;

},{}],9:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.AccessLists = exports.checkMaxInitCodeSize = void 0;
const util_1 = require("@ethereumjs/util");
const types_1 = require("./types");
function checkMaxInitCodeSize(common, length) {
    const maxInitCodeSize = common.param('vm', 'maxInitCodeSize');
    if (maxInitCodeSize && BigInt(length) > maxInitCodeSize) {
        throw new Error(`the initcode size of this transaction is too large: it is ${length} while the max is ${common.param('vm', 'maxInitCodeSize')}`);
    }
}
exports.checkMaxInitCodeSize = checkMaxInitCodeSize;
class AccessLists {
    static getAccessListData(accessList) {
        let AccessListJSON;
        let bufferAccessList;
        if ((0, types_1.isAccessList)(accessList)) {
            AccessListJSON = accessList;
            const newAccessList = [];
            for (let i = 0; i < accessList.length; i++) {
                const item = accessList[i];
                const addressBuffer = (0, util_1.toBuffer)(item.address);
                const storageItems = [];
                for (let index = 0; index < item.storageKeys.length; index++) {
                    storageItems.push((0, util_1.toBuffer)(item.storageKeys[index]));
                }
                newAccessList.push([addressBuffer, storageItems]);
            }
            bufferAccessList = newAccessList;
        }
        else {
            bufferAccessList = accessList ?? [];
            // build the JSON
            const json = [];
            for (let i = 0; i < bufferAccessList.length; i++) {
                const data = bufferAccessList[i];
                const address = (0, util_1.bufferToHex)(data[0]);
                const storageKeys = [];
                for (let item = 0; item < data[1].length; item++) {
                    storageKeys.push((0, util_1.bufferToHex)(data[1][item]));
                }
                const jsonItem = {
                    address,
                    storageKeys,
                };
                json.push(jsonItem);
            }
            AccessListJSON = json;
        }
        return {
            AccessListJSON,
            accessList: bufferAccessList,
        };
    }
    static verifyAccessList(accessList) {
        for (let key = 0; key < accessList.length; key++) {
            const accessListItem = accessList[key];
            const address = accessListItem[0];
            const storageSlots = accessListItem[1];
            if (accessListItem[2] !== undefined) {
                throw new Error('Access list item cannot have 3 elements. It can only have an address, and an array of storage slots.');
            }
            if (address.length !== 20) {
                throw new Error('Invalid EIP-2930 transaction: address length should be 20 bytes');
            }
            for (let storageSlot = 0; storageSlot < storageSlots.length; storageSlot++) {
                if (storageSlots[storageSlot].length !== 32) {
                    throw new Error('Invalid EIP-2930 transaction: storage slot length should be 32 bytes');
                }
            }
        }
    }
    static getAccessListJSON(accessList) {
        const accessListJSON = [];
        for (let index = 0; index < accessList.length; index++) {
            const item = accessList[index];
            const JSONItem = {
                address: '0x' + (0, util_1.setLengthLeft)(item[0], 20).toString('hex'),
                storageKeys: [],
            };
            const storageSlots = item[1];
            for (let slot = 0; slot < storageSlots.length; slot++) {
                const storageSlot = storageSlots[slot];
                JSONItem.storageKeys.push('0x' + (0, util_1.setLengthLeft)(storageSlot, 32).toString('hex'));
            }
            accessListJSON.push(JSONItem);
        }
        return accessListJSON;
    }
    static getDataFeeEIP2930(accessList, common) {
        const accessListStorageKeyCost = common.param('gasPrices', 'accessListStorageKeyCost');
        const accessListAddressCost = common.param('gasPrices', 'accessListAddressCost');
        let slots = 0;
        for (let index = 0; index < accessList.length; index++) {
            const item = accessList[index];
            const storageSlots = item[1];
            slots += storageSlots.length;
        }
        const addresses = accessList.length;
        return addresses * Number(accessListAddressCost) + slots * Number(accessListStorageKeyCost);
    }
}
exports.AccessLists = AccessLists;

},{"./types":8,"@ethereumjs/util":68}],10:[function(require,module,exports){
module.exports={
    "name": "goerli",
    "chainId": 5,
    "networkId": 5,
    "defaultHardfork": "merge",
    "consensus": {
        "type": "poa",
        "algorithm": "clique",
        "clique": {
            "period": 15,
            "epoch": 30000
        }
    },
    "comment": "Cross-client PoA test network",
    "url": "https://github.com/goerli/testnet",
    "genesis": {
        "timestamp": "0x5c51a607",
        "gasLimit": 10485760,
        "difficulty": 1,
        "nonce": "0x0000000000000000",
        "extraData": "0x22466c6578692069732061207468696e6722202d204166726900000000000000e0a2bd4258d2768837baa26a28fe71dc079f84c70000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    },
    "hardforks": [
        {
            "name": "chainstart",
            "block": 0,
            "forkHash": "0xa3f5ab08"
        },
        {
            "name": "homestead",
            "block": 0,
            "forkHash": "0xa3f5ab08"
        },
        {
            "name": "tangerineWhistle",
            "block": 0,
            "forkHash": "0xa3f5ab08"
        },
        {
            "name": "spuriousDragon",
            "block": 0,
            "forkHash": "0xa3f5ab08"
        },
        {
            "name": "byzantium",
            "block": 0,
            "forkHash": "0xa3f5ab08"
        },
        {
            "name": "constantinople",
            "block": 0,
            "forkHash": "0xa3f5ab08"
        },
        {
            "name": "petersburg",
            "block": 0,
            "forkHash": "0xa3f5ab08"
        },
        {
            "name": "istanbul",
            "block": 1561651,
            "forkHash": "0xc25efa5c"
        },
        {
            "name": "berlin",
            "block": 4460644,
            "forkHash": "0x757a1c47"
        },
        {
            "name": "london",
            "block": 5062605,
            "forkHash": "0xb8c6299d"
        },
        {
            "//_comment": "The forkHash will remain same as mergeForkIdTransition is post merge",
            "name": "merge",
            "ttd": "10790000",
            "block": null,
            "forkHash": "0xb8c6299d"
        },
        {
            "name": "mergeForkIdTransition",
            "block": null,
            "forkHash": null
        },
        {
            "name": "shanghai",
            "block": null,
            "forkHash": null
        }
    ],
    "bootstrapNodes": [
        {
            "ip": "51.141.78.53",
            "port": 30303,
            "id": "011f758e6552d105183b1761c5e2dea0111bc20fd5f6422bc7f91e0fabbec9a6595caf6239b37feb773dddd3f87240d99d859431891e4a642cf2a0a9e6cbb98a",
            "location": "",
            "comment": "Upstream bootnode 1"
        },
        {
            "ip": "13.93.54.137",
            "port": 30303,
            "id": "176b9417f511d05b6b2cf3e34b756cf0a7096b3094572a8f6ef4cdcb9d1f9d00683bf0f83347eebdf3b81c3521c2332086d9592802230bf528eaf606a1d9677b",
            "location": "",
            "comment": "Upstream bootnode 2"
        },
        {
            "ip": "94.237.54.114",
            "port": 30313,
            "id": "46add44b9f13965f7b9875ac6b85f016f341012d84f975377573800a863526f4da19ae2c620ec73d11591fa9510e992ecc03ad0751f53cc02f7c7ed6d55c7291",
            "location": "",
            "comment": "Upstream bootnode 3"
        },
        {
            "ip": "18.218.250.66",
            "port": 30313,
            "id": "b5948a2d3e9d486c4d75bf32713221c2bd6cf86463302339299bd227dc2e276cd5a1c7ca4f43a0e9122fe9af884efed563bd2a1fd28661f3b5f5ad7bf1de5949",
            "location": "",
            "comment": "Upstream bootnode 4"
        },
        {
            "ip": "3.11.147.67",
            "port": 30303,
            "id": "a61215641fb8714a373c80edbfa0ea8878243193f57c96eeb44d0bc019ef295abd4e044fd619bfc4c59731a73fb79afe84e9ab6da0c743ceb479cbb6d263fa91",
            "location": "",
            "comment": "Ethereum Foundation bootnode"
        },
        {
            "ip": "51.15.116.226",
            "port": 30303,
            "id": "a869b02cec167211fb4815a82941db2e7ed2936fd90e78619c53eb17753fcf0207463e3419c264e2a1dd8786de0df7e68cf99571ab8aeb7c4e51367ef186b1dd",
            "location": "",
            "comment": "Goerli Initiative bootnode"
        },
        {
            "ip": "51.15.119.157",
            "port": 30303,
            "id": "807b37ee4816ecf407e9112224494b74dd5933625f655962d892f2f0f02d7fbbb3e2a94cf87a96609526f30c998fd71e93e2f53015c558ffc8b03eceaf30ee33",
            "location": "",
            "comment": "Goerli Initiative bootnode"
        },
        {
            "ip": "51.15.119.157",
            "port": 40303,
            "id": "a59e33ccd2b3e52d578f1fbd70c6f9babda2650f0760d6ff3b37742fdcdfdb3defba5d56d315b40c46b70198c7621e63ffa3f987389c7118634b0fefbbdfa7fd",
            "location": "",
            "comment": "Goerli Initiative bootnode"
        }
    ],
    "dnsNetworks": [
        "enrtree://AKA3AM6LPBYEUDMVNU3BSVQJ5AD45Y7YPOHJLEF6W26QOE4VTUDPE@all.goerli.ethdisco.net"
    ]
}

},{}],11:[function(require,module,exports){
module.exports={
    "name": "mainnet",
    "chainId": 1,
    "networkId": 1,
    "defaultHardfork": "merge",
    "consensus": {
        "type": "pow",
        "algorithm": "ethash",
        "ethash": {}
    },
    "comment": "The Ethereum main chain",
    "url": "https://ethstats.net/",
    "genesis": {
        "gasLimit": 5000,
        "difficulty": 17179869184,
        "nonce": "0x0000000000000042",
        "extraData": "0x11bbe8db4e347b4e8c937c1c8370e4b5ed33adb3db69cbdb7a38e1e50b1b82fa"
    },
    "hardforks": [
        {
            "name": "chainstart",
            "block": 0,
            "forkHash": "0xfc64ec04"
        },
        {
            "name": "homestead",
            "block": 1150000,
            "forkHash": "0x97c2c34c"
        },
        {
            "name": "dao",
            "block": 1920000,
            "forkHash": "0x91d1f948"
        },
        {
            "name": "tangerineWhistle",
            "block": 2463000,
            "forkHash": "0x7a64da13"
        },
        {
            "name": "spuriousDragon",
            "block": 2675000,
            "forkHash": "0x3edd5b10"
        },
        {
            "name": "byzantium",
            "block": 4370000,
            "forkHash": "0xa00bc324"
        },
        {
            "name": "constantinople",
            "block": 7280000,
            "forkHash": "0x668db0af"
        },
        {
            "name": "petersburg",
            "block": 7280000,
            "forkHash": "0x668db0af"
        },
        {
            "name": "istanbul",
            "block": 9069000,
            "forkHash": "0x879d6e30"
        },
        {
            "name": "muirGlacier",
            "block": 9200000,
            "forkHash": "0xe029e991"
        },
        {
            "name": "berlin",
            "block": 12244000,
            "forkHash": "0x0eb440f6"
        },
        {
            "name": "london",
            "block": 12965000,
            "forkHash": "0xb715077d"
        },
        {
            "name": "arrowGlacier",
            "block": 13773000,
            "forkHash": "0x20c327fc"
        },
        {
            "name": "grayGlacier",
            "block": 15050000,
            "forkHash": "0xf0afd0e3"
        },
        {
            "name": "mergeForkIdTransition",
            "block": null,
            "forkHash": null
        },
        {
            "name": "merge",
            "ttd": "58750000000000000000000",
            "block": null,
            "forkHash": null
        },
        {
            "name": "shanghai",
            "block": null,
            "forkHash": null
        }
    ],
    "bootstrapNodes": [
        {
            "ip": "18.138.108.67",
            "port": 30303,
            "id": "d860a01f9722d78051619d1e2351aba3f43f943f6f00718d1b9baa4101932a1f5011f16bb2b1bb35db20d6fe28fa0bf09636d26a87d31de9ec6203eeedb1f666",
            "location": "ap-southeast-1-001",
            "comment": "bootnode-aws-ap-southeast-1-001"
        },
        {
            "ip": "3.209.45.79",
            "port": 30303,
            "id": "22a8232c3abc76a16ae9d6c3b164f98775fe226f0917b0ca871128a74a8e9630b458460865bab457221f1d448dd9791d24c4e5d88786180ac185df813a68d4de",
            "location": "us-east-1-001",
            "comment": "bootnode-aws-us-east-1-001"
        },
        {
            "ip": "34.255.23.113",
            "port": 30303,
            "id": "ca6de62fce278f96aea6ec5a2daadb877e51651247cb96ee310a318def462913b653963c155a0ef6c7d50048bba6e6cea881130857413d9f50a621546b590758",
            "location": "eu-west-1-001",
            "comment": "bootnode-aws-eu-west-1-001"
        },
        {
            "ip": "35.158.244.151",
            "port": 30303,
            "id": "279944d8dcd428dffaa7436f25ca0ca43ae19e7bcf94a8fb7d1641651f92d121e972ac2e8f381414b80cc8e5555811c2ec6e1a99bb009b3f53c4c69923e11bd8",
            "location": "eu-central-1-001",
            "comment": "bootnode-aws-eu-central-1-001"
        },
        {
            "ip": "52.187.207.27",
            "port": 30303,
            "id": "8499da03c47d637b20eee24eec3c356c9a2e6148d6fe25ca195c7949ab8ec2c03e3556126b0d7ed644675e78c4318b08691b7b57de10e5f0d40d05b09238fa0a",
            "location": "australiaeast-001",
            "comment": "bootnode-azure-australiaeast-001"
        },
        {
            "ip": "191.234.162.198",
            "port": 30303,
            "id": "103858bdb88756c71f15e9b5e09b56dc1be52f0a5021d46301dbbfb7e130029cc9d0d6f73f693bc29b665770fff7da4d34f3c6379fe12721b5d7a0bcb5ca1fc1",
            "location": "brazilsouth-001",
            "comment": "bootnode-azure-brazilsouth-001"
        },
        {
            "ip": "52.231.165.108",
            "port": 30303,
            "id": "715171f50508aba88aecd1250af392a45a330af91d7b90701c436b618c86aaa1589c9184561907bebbb56439b8f8787bc01f49a7c77276c58c1b09822d75e8e8",
            "location": "koreasouth-001",
            "comment": "bootnode-azure-koreasouth-001"
        },
        {
            "ip": "104.42.217.25",
            "port": 30303,
            "id": "5d6d7cd20d6da4bb83a1d28cadb5d409b64edf314c0335df658c1a54e32c7c4a7ab7823d57c39b6a757556e68ff1df17c748b698544a55cb488b52479a92b60f",
            "location": "westus-001",
            "comment": "bootnode-azure-westus-001"
        }
    ],
    "dnsNetworks": [
        "enrtree://AKA3AM6LPBYEUDMVNU3BSVQJ5AD45Y7YPOHJLEF6W26QOE4VTUDPE@all.mainnet.ethdisco.net"
    ]
}

},{}],12:[function(require,module,exports){
module.exports={
    "name": "rinkeby",
    "chainId": 4,
    "networkId": 4,
    "defaultHardfork": "london",
    "consensus": {
        "type": "poa",
        "algorithm": "clique",
        "clique": {
            "period": 15,
            "epoch": 30000
        }
    },
    "comment": "PoA test network",
    "url": "https://www.rinkeby.io",
    "genesis": {
        "timestamp": "0x58ee40ba",
        "gasLimit": 4700000,
        "difficulty": 1,
        "nonce": "0x0000000000000000",
        "extraData": "0x52657370656374206d7920617574686f7269746168207e452e436172746d616e42eb768f2244c8811c63729a21a3569731535f067ffc57839b00206d1ad20c69a1981b489f772031b279182d99e65703f0076e4812653aab85fca0f00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    },
    "hardforks": [
        {
            "name": "chainstart",
            "block": 0,
            "forkHash": "0x3b8e0691"
        },
        {
            "name": "homestead",
            "block": 1,
            "forkHash": "0x60949295"
        },
        {
            "name": "tangerineWhistle",
            "block": 2,
            "forkHash": "0x8bde40dd"
        },
        {
            "name": "spuriousDragon",
            "block": 3,
            "forkHash": "0xcb3a64bb"
        },
        {
            "name": "byzantium",
            "block": 1035301,
            "forkHash": "0x8d748b57"
        },
        {
            "name": "constantinople",
            "block": 3660663,
            "forkHash": "0xe49cab14"
        },
        {
            "name": "petersburg",
            "block": 4321234,
            "forkHash": "0xafec6b27"
        },
        {
            "name": "istanbul",
            "block": 5435345,
            "forkHash": "0xcbdb8838"
        },
        {
            "name": "berlin",
            "block": 8290928,
            "forkHash": "0x6910c8bd"
        },
        {
            "name": "london",
            "block": 8897988,
            "forkHash": "0x8e29f2f3"
        },
        {
            "name": "merge",
            "block": null,
            "forkHash": null
        },
        {
            "name": "shanghai",
            "block": null,
            "forkHash": null
        }
    ],
    "bootstrapNodes": [
        {
            "ip": "52.169.42.101",
            "port": 30303,
            "id": "a24ac7c5484ef4ed0c5eb2d36620ba4e4aa13b8c84684e1b4aab0cebea2ae45cb4d375b77eab56516d34bfbd3c1a833fc51296ff084b770b94fb9028c4d25ccf",
            "location": "",
            "comment": "IE"
        },
        {
            "ip": "52.3.158.184",
            "port": 30303,
            "id": "343149e4feefa15d882d9fe4ac7d88f885bd05ebb735e547f12e12080a9fa07c8014ca6fd7f373123488102fe5e34111f8509cf0b7de3f5b44339c9f25e87cb8",
            "location": "",
            "comment": "INFURA"
        },
        {
            "ip": "159.89.28.211",
            "port": 30303,
            "id": "b6b28890b006743680c52e64e0d16db57f28124885595fa03a562be1d2bf0f3a1da297d56b13da25fb992888fd556d4c1a27b1f39d531bde7de1921c90061cc6",
            "location": "",
            "comment": "AKASHA"
        }
    ],
    "dnsNetworks": [
        "enrtree://AKA3AM6LPBYEUDMVNU3BSVQJ5AD45Y7YPOHJLEF6W26QOE4VTUDPE@all.rinkeby.ethdisco.net"
    ]
}

},{}],13:[function(require,module,exports){
module.exports={
    "name": "ropsten",
    "chainId": 3,
    "networkId": 3,
    "defaultHardfork": "merge",
    "consensus": {
        "type": "pow",
        "algorithm": "ethash",
        "ethash": {}
    },
    "comment": "PoW test network",
    "url": "https://github.com/ethereum/ropsten",
    "genesis": {
        "gasLimit": 16777216,
        "difficulty": 1048576,
        "nonce": "0x0000000000000042",
        "extraData": "0x3535353535353535353535353535353535353535353535353535353535353535"
    },
    "hardforks": [
        {
            "name": "chainstart",
            "block": 0,
            "forkHash": "0x30c7ddbc"
        },
        {
            "name": "homestead",
            "block": 0,
            "forkHash": "0x30c7ddbc"
        },
        {
            "name": "tangerineWhistle",
            "block": 0,
            "forkHash": "0x30c7ddbc"
        },
        {
            "name": "spuriousDragon",
            "block": 10,
            "forkHash": "0x63760190"
        },
        {
            "name": "byzantium",
            "block": 1700000,
            "forkHash": "0x3ea159c7"
        },
        {
            "name": "constantinople",
            "block": 4230000,
            "forkHash": "0x97b544f3"
        },
        {
            "name": "petersburg",
            "block": 4939394,
            "forkHash": "0xd6e2149b"
        },
        {
            "name": "istanbul",
            "block": 6485846,
            "forkHash": "0x4bc66396"
        },
        {
            "name": "muirGlacier",
            "block": 7117117,
            "forkHash": "0x6727ef90"
        },
        {
            "name": "berlin",
            "block": 9812189,
            "forkHash": "0xa157d377"
        },
        {
            "name": "london",
            "block": 10499401,
            "forkHash": "0x7119b6b3"
        },
        {
            "//_comment": "The forkHash will remain same as mergeForkIdTransition is post merge",
            "name": "merge",
            "ttd": "50000000000000000",
            "block": null,
            "forkHash": "0x7119b6b3"
        },
        {
            "name": "mergeForkIdTransition",
            "block": null,
            "forkHash": null
        },
        {
            "name": "shanghai",
            "block": null,
            "forkHash": null
        }
    ],
    "bootstrapNodes": [
        {
            "ip": "52.176.7.10",
            "port": 30303,
            "id": "30b7ab30a01c124a6cceca36863ece12c4f5fa68e3ba9b0b51407ccc002eeed3b3102d20a88f1c1d3c3154e2449317b8ef95090e77b312d5cc39354f86d5d606",
            "location": "",
            "comment": "US-Azure geth"
        },
        {
            "ip": "52.176.100.77",
            "port": 30303,
            "id": "865a63255b3bb68023b6bffd5095118fcc13e79dcf014fe4e47e065c350c7cc72af2e53eff895f11ba1bbb6a2b33271c1116ee870f266618eadfc2e78aa7349c",
            "location": "",
            "comment": "US-Azure parity"
        },
        {
            "ip": "52.232.243.152",
            "port": 30303,
            "id": "6332792c4a00e3e4ee0926ed89e0d27ef985424d97b6a45bf0f23e51f0dcb5e66b875777506458aea7af6f9e4ffb69f43f3778ee73c81ed9d34c51c4b16b0b0f",
            "location": "",
            "comment": "Parity"
        },
        {
            "ip": "192.81.208.223",
            "port": 30303,
            "id": "94c15d1b9e2fe7ce56e458b9a3b672ef11894ddedd0c6f247e0f1d3487f52b66208fb4aeb8179fce6e3a749ea93ed147c37976d67af557508d199d9594c35f09",
            "location": "",
            "comment": "@gpip"
        }
    ],
    "dnsNetworks": [
        "enrtree://AKA3AM6LPBYEUDMVNU3BSVQJ5AD45Y7YPOHJLEF6W26QOE4VTUDPE@all.ropsten.ethdisco.net"
    ]
}

},{}],14:[function(require,module,exports){
module.exports={
    "name": "sepolia",
    "chainId": 11155111,
    "networkId": 11155111,
    "defaultHardfork": "merge",
    "consensus": {
        "type": "pow",
        "algorithm": "ethash",
        "ethash": {}
    },
    "comment": "PoW test network to replace Ropsten",
    "url": "https://github.com/ethereum/go-ethereum/pull/23730",
    "genesis": {
        "timestamp": "0x6159af19",
        "gasLimit": 30000000,
        "difficulty": 131072,
        "nonce": "0x0000000000000000",
        "extraData": "0x5365706f6c69612c20417468656e732c204174746963612c2047726565636521"
    },
    "hardforks": [
        {
            "name": "chainstart",
            "block": 0,
            "forkHash": "0xfe3366e7"
        },
        {
            "name": "homestead",
            "block": 0,
            "forkHash": "0xfe3366e7"
        },
        {
            "name": "tangerineWhistle",
            "block": 0,
            "forkHash": "0xfe3366e7"
        },
        {
            "name": "spuriousDragon",
            "block": 0,
            "forkHash": "0xfe3366e7"
        },
        {
            "name": "byzantium",
            "block": 0,
            "forkHash": "0xfe3366e7"
        },
        {
            "name": "constantinople",
            "block": 0,
            "forkHash": "0xfe3366e7"
        },
        {
            "name": "petersburg",
            "block": 0,
            "forkHash": "0xfe3366e7"
        },
        {
            "name": "istanbul",
            "block": 0,
            "forkHash": "0xfe3366e7"
        },
        {
            "name": "muirGlacier",
            "block": 0,
            "forkHash": "0xfe3366e7"
        },
        {
            "name": "berlin",
            "block": 0,
            "forkHash": "0xfe3366e7"
        },
        {
            "name": "london",
            "block": 0,
            "forkHash": "0xfe3366e7"
        },
        {
            "//_comment": "The forkHash will remain same as mergeForkIdTransition is post merge",
            "name": "merge",
            "ttd": "17000000000000000",
            "block": null,
            "forkHash": "0xfe3366e7"
        },
        {
            "name": "mergeForkIdTransition",
            "block": 1735371,
            "forkHash": "0xb96cbd13"
        },
        {
            "name": "shanghai",
            "block": null,
            "forkHash": null
        }
    ],
    "bootstrapNodes": [
        {
            "ip": "18.168.182.86",
            "port": 30303,
            "id": "9246d00bc8fd1742e5ad2428b80fc4dc45d786283e05ef6edbd9002cbc335d40998444732fbe921cb88e1d2c73d1b1de53bae6a2237996e9bfe14f871baf7066",
            "location": "",
            "comment": "geth"
        },
        {
            "ip": "52.14.151.177",
            "port": 30303,
            "id": "ec66ddcf1a974950bd4c782789a7e04f8aa7110a72569b6e65fcd51e937e74eed303b1ea734e4d19cfaec9fbff9b6ee65bf31dcb50ba79acce9dd63a6aca61c7",
            "location": "",
            "comment": "besu"
        },
        {
            "ip": "165.22.196.173",
            "port": 30303,
            "id": "ce970ad2e9daa9e14593de84a8b49da3d54ccfdf83cbc4fe519cb8b36b5918ed4eab087dedd4a62479b8d50756b492d5f762367c8d20329a7854ec01547568a6",
            "location": "",
            "comment": "EF"
        },
        {
            "ip": "65.108.95.67",
            "port": 30303,
            "id": "075503b13ed736244896efcde2a992ec0b451357d46cb7a8132c0384721742597fc8f0d91bbb40bb52e7d6e66728d36a1fda09176294e4a30cfac55dcce26bc6",
            "location": "",
            "comment": "lodestar"
        }
    ],
    "dnsNetworks": [
        "enrtree://AKA3AM6LPBYEUDMVNU3BSVQJ5AD45Y7YPOHJLEF6W26QOE4VTUDPE@all.sepolia.ethdisco.net"
    ]
}

},{}],15:[function(require,module,exports){
(function (Buffer){(function (){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Common = void 0;
const util_1 = require("@ethereumjs/util");
const crc_32_1 = require("crc-32");
const events_1 = require("events");
const goerli = require("./chains/goerli.json");
const mainnet = require("./chains/mainnet.json");
const rinkeby = require("./chains/rinkeby.json");
const ropsten = require("./chains/ropsten.json");
const sepolia = require("./chains/sepolia.json");
const eips_1 = require("./eips");
const enums_1 = require("./enums");
const hardforks_1 = require("./hardforks");
/**
 * Common class to access chain and hardfork parameters and to provide
 * a unified and shared view on the network and hardfork state.
 *
 * Use the {@link Common.custom} static constructor for creating simple
 * custom chain {@link Common} objects (more complete custom chain setups
 * can be created via the main constructor and the {@link CommonOpts.customChains} parameter).
 */
class Common extends events_1.EventEmitter {
    constructor(opts) {
        super();
        this._eips = [];
        this._customChains = opts.customChains ?? [];
        this._chainParams = this.setChain(opts.chain);
        this.DEFAULT_HARDFORK = this._chainParams.defaultHardfork ?? enums_1.Hardfork.Merge;
        this._hardfork = this.DEFAULT_HARDFORK;
        if (opts.hardfork !== undefined) {
            this.setHardfork(opts.hardfork);
        }
        if (opts.eips) {
            this.setEIPs(opts.eips);
        }
    }
    /**
     * Creates a {@link Common} object for a custom chain, based on a standard one.
     *
     * It uses all the {@link Chain} parameters from the {@link baseChain} option except the ones overridden
     * in a provided {@link chainParamsOrName} dictionary. Some usage example:
     *
     * ```javascript
     * Common.custom({chainId: 123})
     * ```
     *
     * There are also selected supported custom chains which can be initialized by using one of the
     * {@link CustomChains} for {@link chainParamsOrName}, e.g.:
     *
     * ```javascript
     * Common.custom(CustomChains.MaticMumbai)
     * ```
     *
     * Note that these supported custom chains only provide some base parameters (usually the chain and
     * network ID and a name) and can only be used for selected use cases (e.g. sending a tx with
     * the `@ethereumjs/tx` library to a Layer-2 chain).
     *
     * @param chainParamsOrName Custom parameter dict (`name` will default to `custom-chain`) or string with name of a supported custom chain
     * @param opts Custom chain options to set the {@link CustomCommonOpts.baseChain}, selected {@link CustomCommonOpts.hardfork} and others
     */
    static custom(chainParamsOrName, opts = {}) {
        const baseChain = opts.baseChain ?? 'mainnet';
        const standardChainParams = { ...Common._getChainParams(baseChain) };
        standardChainParams['name'] = 'custom-chain';
        if (typeof chainParamsOrName !== 'string') {
            return new Common({
                chain: {
                    ...standardChainParams,
                    ...chainParamsOrName,
                },
                ...opts,
            });
        }
        else {
            if (chainParamsOrName === enums_1.CustomChain.PolygonMainnet) {
                return Common.custom({
                    name: enums_1.CustomChain.PolygonMainnet,
                    chainId: 137,
                    networkId: 137,
                }, opts);
            }
            if (chainParamsOrName === enums_1.CustomChain.PolygonMumbai) {
                return Common.custom({
                    name: enums_1.CustomChain.PolygonMumbai,
                    chainId: 80001,
                    networkId: 80001,
                }, opts);
            }
            if (chainParamsOrName === enums_1.CustomChain.ArbitrumRinkebyTestnet) {
                return Common.custom({
                    name: enums_1.CustomChain.ArbitrumRinkebyTestnet,
                    chainId: 421611,
                    networkId: 421611,
                }, opts);
            }
            if (chainParamsOrName === enums_1.CustomChain.xDaiChain) {
                return Common.custom({
                    name: enums_1.CustomChain.xDaiChain,
                    chainId: 100,
                    networkId: 100,
                }, opts);
            }
            if (chainParamsOrName === enums_1.CustomChain.OptimisticKovan) {
                return Common.custom({
                    name: enums_1.CustomChain.OptimisticKovan,
                    chainId: 69,
                    networkId: 69,
                }, 
                // Optimism has not implemented the London hardfork yet (targeting Q1.22)
                { hardfork: enums_1.Hardfork.Berlin, ...opts });
            }
            if (chainParamsOrName === enums_1.CustomChain.OptimisticEthereum) {
                return Common.custom({
                    name: enums_1.CustomChain.OptimisticEthereum,
                    chainId: 10,
                    networkId: 10,
                }, 
                // Optimism has not implemented the London hardfork yet (targeting Q1.22)
                { hardfork: enums_1.Hardfork.Berlin, ...opts });
            }
            throw new Error(`Custom chain ${chainParamsOrName} not supported`);
        }
    }
    /**
     * Static method to determine if a {@link chainId} is supported as a standard chain
     * @param chainId bigint id (`1`) of a standard chain
     * @returns boolean
     */
    static isSupportedChainId(chainId) {
        const initializedChains = this._getInitializedChains();
        return Boolean(initializedChains['names'][chainId.toString()]);
    }
    static _getChainParams(chain, customChains) {
        const initializedChains = this._getInitializedChains(customChains);
        if (typeof chain === 'number' || typeof chain === 'bigint') {
            chain = chain.toString();
            if (initializedChains['names'][chain]) {
                const name = initializedChains['names'][chain];
                return initializedChains[name];
            }
            throw new Error(`Chain with ID ${chain} not supported`);
        }
        if (initializedChains[chain] !== undefined) {
            return initializedChains[chain];
        }
        throw new Error(`Chain with name ${chain} not supported`);
    }
    /**
     * Sets the chain
     * @param chain String ('mainnet') or Number (1) chain representation.
     *              Or, a Dictionary of chain parameters for a private network.
     * @returns The dictionary with parameters set as chain
     */
    setChain(chain) {
        if (typeof chain === 'number' || typeof chain === 'bigint' || typeof chain === 'string') {
            this._chainParams = Common._getChainParams(chain, this._customChains);
        }
        else if (typeof chain === 'object') {
            if (this._customChains.length > 0) {
                throw new Error('Chain must be a string, number, or bigint when initialized with customChains passed in');
            }
            const required = ['networkId', 'genesis', 'hardforks', 'bootstrapNodes'];
            for (const param of required) {
                if (!(param in chain)) {
                    throw new Error(`Missing required chain parameter: ${param}`);
                }
            }
            this._chainParams = chain;
        }
        else {
            throw new Error('Wrong input format');
        }
        for (const hf of this.hardforks()) {
            if (hf.block === undefined) {
                throw new Error(`Hardfork cannot have undefined block number`);
            }
        }
        return this._chainParams;
    }
    /**
     * Sets the hardfork to get params for
     * @param hardfork String identifier (e.g. 'byzantium') or {@link Hardfork} enum
     */
    setHardfork(hardfork) {
        let existing = false;
        for (const hfChanges of hardforks_1.hardforks) {
            if (hfChanges[0] === hardfork) {
                if (this._hardfork !== hardfork) {
                    this._hardfork = hardfork;
                    this.emit('hardforkChanged', hardfork);
                }
                existing = true;
            }
        }
        if (!existing) {
            throw new Error(`Hardfork with name ${hardfork} not supported`);
        }
    }
    /**
     * Returns the hardfork based on the block number or an optional
     * total difficulty (Merge HF) provided.
     *
     * An optional TD takes precedence in case the corresponding HF block
     * is set to `null` or otherwise needs to match (if not an error
     * will be thrown).
     *
     * @param blockNumber
     * @param td
     * @returns The name of the HF
     */
    getHardforkByBlockNumber(blockNumber, td) {
        blockNumber = (0, util_1.toType)(blockNumber, util_1.TypeOutput.BigInt);
        td = (0, util_1.toType)(td, util_1.TypeOutput.BigInt);
        let hardfork = enums_1.Hardfork.Chainstart;
        let minTdHF;
        let maxTdHF;
        let previousHF;
        for (const hf of this.hardforks()) {
            // Skip comparison for not applied HFs
            if (hf.block === null) {
                if (td !== undefined && td !== null && hf.ttd !== undefined && hf.ttd !== null) {
                    if (td >= BigInt(hf.ttd)) {
                        return hf.name;
                    }
                }
                continue;
            }
            if (blockNumber >= BigInt(hf.block)) {
                hardfork = hf.name;
            }
            if (td && (typeof hf.ttd === 'string' || typeof hf.ttd === 'bigint')) {
                if (td >= BigInt(hf.ttd)) {
                    minTdHF = hf.name;
                }
                else {
                    maxTdHF = previousHF;
                }
            }
            previousHF = hf.name;
        }
        if (td) {
            let msgAdd = `block number: ${blockNumber} (-> ${hardfork}), `;
            if (minTdHF !== undefined) {
                if (!this.hardforkGteHardfork(hardfork, minTdHF)) {
                    const msg = 'HF determined by block number is lower than the minimum total difficulty HF';
                    msgAdd += `total difficulty: ${td} (-> ${minTdHF})`;
                    throw new Error(`${msg}: ${msgAdd}`);
                }
            }
            if (maxTdHF !== undefined) {
                if (!this.hardforkGteHardfork(maxTdHF, hardfork)) {
                    const msg = 'Maximum HF determined by total difficulty is lower than the block number HF';
                    msgAdd += `total difficulty: ${td} (-> ${maxTdHF})`;
                    throw new Error(`${msg}: ${msgAdd}`);
                }
            }
        }
        return hardfork;
    }
    /**
     * Sets a new hardfork based on the block number or an optional
     * total difficulty (Merge HF) provided.
     *
     * An optional TD takes precedence in case the corresponding HF block
     * is set to `null` or otherwise needs to match (if not an error
     * will be thrown).
     *
     * @param blockNumber
     * @param td
     * @returns The name of the HF set
     */
    setHardforkByBlockNumber(blockNumber, td) {
        const hardfork = this.getHardforkByBlockNumber(blockNumber, td);
        this.setHardfork(hardfork);
        return hardfork;
    }
    /**
     * Internal helper function, returns the params for the given hardfork for the chain set
     * @param hardfork Hardfork name
     * @returns Dictionary with hardfork params or null if hardfork not on chain
     */
    _getHardfork(hardfork) {
        const hfs = this.hardforks();
        for (const hf of hfs) {
            if (hf['name'] === hardfork)
                return hf;
        }
        return null;
    }
    /**
     * Sets the active EIPs
     * @param eips
     */
    setEIPs(eips = []) {
        for (const eip of eips) {
            if (!(eip in eips_1.EIPs)) {
                throw new Error(`${eip} not supported`);
            }
            const minHF = this.gteHardfork(eips_1.EIPs[eip]['minimumHardfork']);
            if (!minHF) {
                throw new Error(`${eip} cannot be activated on hardfork ${this.hardfork()}, minimumHardfork: ${minHF}`);
            }
            if (eips_1.EIPs[eip].requiredEIPs !== undefined) {
                for (const elem of eips_1.EIPs[eip].requiredEIPs) {
                    if (!(eips.includes(elem) || this.isActivatedEIP(elem))) {
                        throw new Error(`${eip} requires EIP ${elem}, but is not included in the EIP list`);
                    }
                }
            }
        }
        this._eips = eips;
    }
    /**
     * Returns a parameter for the current chain setup
     *
     * If the parameter is present in an EIP, the EIP always takes precendence.
     * Otherwise the parameter if taken from the latest applied HF with
     * a change on the respective parameter.
     *
     * @param topic Parameter topic ('gasConfig', 'gasPrices', 'vm', 'pow')
     * @param name Parameter name (e.g. 'minGasLimit' for 'gasConfig' topic)
     * @returns The value requested or `BigInt(0)` if not found
     */
    param(topic, name) {
        // TODO: consider the case that different active EIPs
        // can change the same parameter
        let value;
        for (const eip of this._eips) {
            value = this.paramByEIP(topic, name, eip);
            if (value !== undefined)
                return value;
        }
        return this.paramByHardfork(topic, name, this._hardfork);
    }
    /**
     * Returns the parameter corresponding to a hardfork
     * @param topic Parameter topic ('gasConfig', 'gasPrices', 'vm', 'pow')
     * @param name Parameter name (e.g. 'minGasLimit' for 'gasConfig' topic)
     * @param hardfork Hardfork name
     * @returns The value requested or `BigInt(0)` if not found
     */
    paramByHardfork(topic, name, hardfork) {
        let value = null;
        for (const hfChanges of hardforks_1.hardforks) {
            // EIP-referencing HF file (e.g. berlin.json)
            if ('eips' in hfChanges[1]) {
                const hfEIPs = hfChanges[1]['eips'];
                for (const eip of hfEIPs) {
                    const valueEIP = this.paramByEIP(topic, name, eip);
                    value = typeof valueEIP === 'bigint' ? valueEIP : value;
                }
                // Parameter-inlining HF file (e.g. istanbul.json)
            }
            else {
                if (hfChanges[1][topic] === undefined) {
                    throw new Error(`Topic ${topic} not defined`);
                }
                if (hfChanges[1][topic][name] !== undefined) {
                    value = hfChanges[1][topic][name].v;
                }
            }
            if (hfChanges[0] === hardfork)
                break;
        }
        return BigInt(value ?? 0);
    }
    /**
     * Returns a parameter corresponding to an EIP
     * @param topic Parameter topic ('gasConfig', 'gasPrices', 'vm', 'pow')
     * @param name Parameter name (e.g. 'minGasLimit' for 'gasConfig' topic)
     * @param eip Number of the EIP
     * @returns The value requested or `undefined` if not found
     */
    paramByEIP(topic, name, eip) {
        if (!(eip in eips_1.EIPs)) {
            throw new Error(`${eip} not supported`);
        }
        const eipParams = eips_1.EIPs[eip];
        if (!(topic in eipParams)) {
            throw new Error(`Topic ${topic} not defined`);
        }
        if (eipParams[topic][name] === undefined) {
            return undefined;
        }
        const value = eipParams[topic][name].v;
        return BigInt(value);
    }
    /**
     * Returns a parameter for the hardfork active on block number or
     * optional provided total difficulty (Merge HF)
     * @param topic Parameter topic
     * @param name Parameter name
     * @param blockNumber Block number
     * @param td Total difficulty
     *    * @returns The value requested or `BigInt(0)` if not found
     */
    paramByBlock(topic, name, blockNumber, td) {
        const hardfork = this.getHardforkByBlockNumber(blockNumber, td);
        return this.paramByHardfork(topic, name, hardfork);
    }
    /**
     * Checks if an EIP is activated by either being included in the EIPs
     * manually passed in with the {@link CommonOpts.eips} or in a
     * hardfork currently being active
     *
     * Note: this method only works for EIPs being supported
     * by the {@link CommonOpts.eips} constructor option
     * @param eip
     */
    isActivatedEIP(eip) {
        if (this.eips().includes(eip)) {
            return true;
        }
        for (const hfChanges of hardforks_1.hardforks) {
            const hf = hfChanges[1];
            if (this.gteHardfork(hf['name']) && 'eips' in hf) {
                if (hf['eips'].includes(eip)) {
                    return true;
                }
            }
        }
        return false;
    }
    /**
     * Checks if set or provided hardfork is active on block number
     * @param hardfork Hardfork name or null (for HF set)
     * @param blockNumber
     * @returns True if HF is active on block number
     */
    hardforkIsActiveOnBlock(hardfork, blockNumber) {
        blockNumber = (0, util_1.toType)(blockNumber, util_1.TypeOutput.BigInt);
        hardfork = hardfork ?? this._hardfork;
        const hfBlock = this.hardforkBlock(hardfork);
        if (typeof hfBlock === 'bigint' && hfBlock !== BigInt(0) && blockNumber >= hfBlock) {
            return true;
        }
        return false;
    }
    /**
     * Alias to hardforkIsActiveOnBlock when hardfork is set
     * @param blockNumber
     * @returns True if HF is active on block number
     */
    activeOnBlock(blockNumber) {
        return this.hardforkIsActiveOnBlock(null, blockNumber);
    }
    /**
     * Sequence based check if given or set HF1 is greater than or equal HF2
     * @param hardfork1 Hardfork name or null (if set)
     * @param hardfork2 Hardfork name
     * @param opts Hardfork options
     * @returns True if HF1 gte HF2
     */
    hardforkGteHardfork(hardfork1, hardfork2) {
        hardfork1 = hardfork1 ?? this._hardfork;
        const hardforks = this.hardforks();
        let posHf1 = -1, posHf2 = -1;
        let index = 0;
        for (const hf of hardforks) {
            if (hf['name'] === hardfork1)
                posHf1 = index;
            if (hf['name'] === hardfork2)
                posHf2 = index;
            index += 1;
        }
        return posHf1 >= posHf2 && posHf2 !== -1;
    }
    /**
     * Alias to hardforkGteHardfork when hardfork is set
     * @param hardfork Hardfork name
     * @returns True if hardfork set is greater than hardfork provided
     */
    gteHardfork(hardfork) {
        return this.hardforkGteHardfork(null, hardfork);
    }
    /**
     * Returns the hardfork change block for hardfork provided or set
     * @param hardfork Hardfork name, optional if HF set
     * @returns Block number or null if unscheduled
     */
    hardforkBlock(hardfork) {
        hardfork = hardfork ?? this._hardfork;
        const block = this._getHardfork(hardfork)?.['block'];
        if (block === undefined || block === null) {
            return null;
        }
        return BigInt(block);
    }
    /**
     * Returns the hardfork change block for eip
     * @param eip EIP number
     * @returns Block number or null if unscheduled
     */
    eipBlock(eip) {
        for (const hfChanges of hardforks_1.hardforks) {
            const hf = hfChanges[1];
            if ('eips' in hf) {
                // eslint-disable-next-line @typescript-eslint/strict-boolean-expressions
                if (hf['eips'].includes(eip)) {
                    return this.hardforkBlock(hfChanges[0]);
                }
            }
        }
        return null;
    }
    /**
     * Returns the hardfork change total difficulty (Merge HF) for hardfork provided or set
     * @param hardfork Hardfork name, optional if HF set
     * @returns Total difficulty or null if no set
     */
    hardforkTTD(hardfork) {
        hardfork = hardfork ?? this._hardfork;
        const ttd = this._getHardfork(hardfork)?.['ttd'];
        if (ttd === undefined || ttd === null) {
            return null;
        }
        return BigInt(ttd);
    }
    /**
     * True if block number provided is the hardfork (given or set) change block
     * @param blockNumber Number of the block to check
     * @param hardfork Hardfork name, optional if HF set
     * @returns True if blockNumber is HF block
     */
    isHardforkBlock(blockNumber, hardfork) {
        blockNumber = (0, util_1.toType)(blockNumber, util_1.TypeOutput.BigInt);
        hardfork = hardfork ?? this._hardfork;
        const block = this.hardforkBlock(hardfork);
        return typeof block === 'bigint' && block !== BigInt(0) ? block === blockNumber : false;
    }
    /**
     * Returns the change block for the next hardfork after the hardfork provided or set
     * @param hardfork Hardfork name, optional if HF set
     * @returns Block number or null if not available
     */
    nextHardforkBlock(hardfork) {
        hardfork = hardfork ?? this._hardfork;
        const hfBlock = this.hardforkBlock(hardfork);
        if (hfBlock === null) {
            return null;
        }
        // Next fork block number or null if none available
        // Logic: if accumulator is still null and on the first occurrence of
        // a block greater than the current hfBlock set the accumulator,
        // pass on the accumulator as the final result from this time on
        const nextHfBlock = this.hardforks().reduce((acc, hf) => {
            const block = BigInt(typeof hf.block !== 'number' ? 0 : hf.block);
            return block > hfBlock && acc === null ? block : acc;
        }, null);
        return nextHfBlock;
    }
    /**
     * True if block number provided is the hardfork change block following the hardfork given or set
     * @param blockNumber Number of the block to check
     * @param hardfork Hardfork name, optional if HF set
     * @returns True if blockNumber is HF block
     */
    isNextHardforkBlock(blockNumber, hardfork) {
        blockNumber = (0, util_1.toType)(blockNumber, util_1.TypeOutput.BigInt);
        hardfork = hardfork ?? this._hardfork;
        const nextHardforkBlock = this.nextHardforkBlock(hardfork);
        return nextHardforkBlock === null ? false : nextHardforkBlock === blockNumber;
    }
    /**
     * Internal helper function to calculate a fork hash
     * @param hardfork Hardfork name
     * @param genesisHash Genesis block hash of the chain
     * @returns Fork hash as hex string
     */
    _calcForkHash(hardfork, genesisHash) {
        let hfBuffer = Buffer.alloc(0);
        let prevBlock = 0;
        for (const hf of this.hardforks()) {
            const block = hf.block;
            // Skip for chainstart (0), not applied HFs (null) and
            // when already applied on same block number HFs
            if (typeof block === 'number' && block !== 0 && block !== prevBlock) {
                const hfBlockBuffer = Buffer.from(block.toString(16).padStart(16, '0'), 'hex');
                hfBuffer = Buffer.concat([hfBuffer, hfBlockBuffer]);
            }
            if (hf.name === hardfork)
                break;
            if (typeof block === 'number') {
                prevBlock = block;
            }
        }
        const inputBuffer = Buffer.concat([genesisHash, hfBuffer]);
        // CRC32 delivers result as signed (negative) 32-bit integer,
        // convert to hex string
        const forkhash = (0, util_1.intToBuffer)((0, crc_32_1.buf)(inputBuffer) >>> 0).toString('hex');
        return `0x${forkhash}`;
    }
    /**
     * Returns an eth/64 compliant fork hash (EIP-2124)
     * @param hardfork Hardfork name, optional if HF set
     * @param genesisHash Genesis block hash of the chain, optional if already defined and not needed to be calculated
     */
    forkHash(hardfork, genesisHash) {
        hardfork = hardfork ?? this._hardfork;
        const data = this._getHardfork(hardfork);
        if (data === null || (data?.block === null && data?.ttd === undefined)) {
            const msg = 'No fork hash calculation possible for future hardfork';
            throw new Error(msg);
        }
        if (data?.forkHash !== null && data?.forkHash !== undefined) {
            return data.forkHash;
        }
        if (!genesisHash)
            throw new Error('genesisHash required for forkHash calculation');
        return this._calcForkHash(hardfork, genesisHash);
    }
    /**
     *
     * @param forkHash Fork hash as a hex string
     * @returns Array with hardfork data (name, block, forkHash)
     */
    hardforkForForkHash(forkHash) {
        const resArray = this.hardforks().filter((hf) => {
            return hf.forkHash === forkHash;
        });
        return resArray.length >= 1 ? resArray[resArray.length - 1] : null;
    }
    /**
     * Returns the Genesis parameters of the current chain
     * @returns Genesis dictionary
     */
    genesis() {
        return this._chainParams.genesis;
    }
    /**
     * Returns the hardforks for current chain
     * @returns {Array} Array with arrays of hardforks
     */
    hardforks() {
        return this._chainParams.hardforks;
    }
    /**
     * Returns bootstrap nodes for the current chain
     * @returns {Dictionary} Dict with bootstrap nodes
     */
    bootstrapNodes() {
        return this._chainParams.bootstrapNodes;
    }
    /**
     * Returns DNS networks for the current chain
     * @returns {String[]} Array of DNS ENR urls
     */
    dnsNetworks() {
        return this._chainParams.dnsNetworks;
    }
    /**
     * Returns the hardfork set
     * @returns Hardfork name
     */
    hardfork() {
        return this._hardfork;
    }
    /**
     * Returns the Id of current chain
     * @returns chain Id
     */
    chainId() {
        return BigInt(this._chainParams.chainId);
    }
    /**
     * Returns the name of current chain
     * @returns chain name (lower case)
     */
    chainName() {
        return this._chainParams.name;
    }
    /**
     * Returns the Id of current network
     * @returns network Id
     */
    networkId() {
        return BigInt(this._chainParams.networkId);
    }
    /**
     * Returns the active EIPs
     * @returns List of EIPs
     */
    eips() {
        return this._eips;
    }
    /**
     * Returns the consensus type of the network
     * Possible values: "pow"|"poa"|"pos"
     *
     * Note: This value can update along a Hardfork.
     */
    consensusType() {
        const hardfork = this.hardfork();
        let value;
        for (const hfChanges of hardforks_1.hardforks) {
            if ('consensus' in hfChanges[1]) {
                value = hfChanges[1]['consensus']['type'];
            }
            if (hfChanges[0] === hardfork)
                break;
        }
        return value ?? this._chainParams['consensus']['type'];
    }
    /**
     * Returns the concrete consensus implementation
     * algorithm or protocol for the network
     * e.g. "ethash" for "pow" consensus type,
     * "clique" for "poa" consensus type or
     * "casper" for "pos" consensus type.
     *
     * Note: This value can update along a Hardfork.
     */
    consensusAlgorithm() {
        const hardfork = this.hardfork();
        let value;
        for (const hfChanges of hardforks_1.hardforks) {
            if ('consensus' in hfChanges[1]) {
                value = hfChanges[1]['consensus']['algorithm'];
            }
            if (hfChanges[0] === hardfork)
                break;
        }
        return value ?? this._chainParams['consensus']['algorithm'];
    }
    /**
     * Returns a dictionary with consensus configuration
     * parameters based on the consensus algorithm
     *
     * Expected returns (parameters must be present in
     * the respective chain json files):
     *
     * ethash: -
     * clique: period, epoch
     * aura: -
     * casper: -
     *
     * Note: This value can update along a Hardfork.
     */
    consensusConfig() {
        const hardfork = this.hardfork();
        let value;
        for (const hfChanges of hardforks_1.hardforks) {
            if ('consensus' in hfChanges[1]) {
                // The config parameter is named after the respective consensus algorithm
                value = hfChanges[1]['consensus'][hfChanges[1]['consensus']['algorithm']];
            }
            if (hfChanges[0] === hardfork)
                break;
        }
        return value ?? this._chainParams['consensus'][this.consensusAlgorithm()];
    }
    /**
     * Returns a deep copy of this {@link Common} instance.
     */
    copy() {
        const copy = Object.assign(Object.create(Object.getPrototypeOf(this)), this);
        copy.removeAllListeners();
        return copy;
    }
    static _getInitializedChains(customChains) {
        const names = {};
        for (const [name, id] of Object.entries(enums_1.Chain)) {
            names[id] = name.toLowerCase();
        }
        const chains = { mainnet, ropsten, rinkeby, goerli, sepolia };
        if (customChains) {
            for (const chain of customChains) {
                const { name } = chain;
                names[chain.chainId.toString()] = name;
                chains[name] = chain;
            }
        }
        chains.names = names;
        return chains;
    }
}
exports.Common = Common;

}).call(this)}).call(this,require("buffer").Buffer)
},{"./chains/goerli.json":10,"./chains/mainnet.json":11,"./chains/rinkeby.json":12,"./chains/ropsten.json":13,"./chains/sepolia.json":14,"./eips":39,"./enums":40,"./hardforks":49,"@ethereumjs/util":68,"buffer":89,"crc-32":84,"events":90}],16:[function(require,module,exports){
module.exports={
    "name": "EIP-1153",
    "number": 1153,
    "comment": "Transient Storage",
    "url": "https://eips.ethereum.org/EIPS/eip-1153",
    "status": "Review",
    "minimumHardfork": "chainstart",
    "requiredEIPs": [],
    "gasConfig": {},
    "gasPrices": {
        "tstore": {
            "v": 100,
            "d": "Base fee of the TSTORE opcode"
        },
        "tload": {
            "v": 100,
            "d": "Base fee of the TLOAD opcode"
        }
    },
    "vm": {},
    "pow": {}
}

},{}],17:[function(require,module,exports){
module.exports={
    "name": "EIP-1559",
    "number": 1559,
    "comment": "Fee market change for ETH 1.0 chain",
    "url": "https://eips.ethereum.org/EIPS/eip-1559",
    "status": "Final",
    "minimumHardfork": "berlin",
    "requiredEIPs": [2930],
    "gasConfig": {
        "baseFeeMaxChangeDenominator": {
            "v": 8,
            "d": "Maximum base fee change denominator"
        },
        "elasticityMultiplier": {
            "v": 2,
            "d": "Maximum block gas target elasticity"
        },
        "initialBaseFee": {
            "v": 1000000000,
            "d": "Initial base fee on first EIP1559 block"
        }
    },
    "gasPrices": {},
    "vm": {},
    "pow": {}
}

},{}],18:[function(require,module,exports){
module.exports={
    "name": "EIP-2315",
    "number": 2315,
    "comment": "Simple subroutines for the EVM",
    "url": "https://eips.ethereum.org/EIPS/eip-2315",
    "status": "Draft",
    "minimumHardfork": "istanbul",
    "gasConfig": {},
    "gasPrices": {
        "beginsub": {
            "v": 2,
            "d": "Base fee of the BEGINSUB opcode"
        },
        "returnsub": {
            "v": 5,
            "d": "Base fee of the RETURNSUB opcode"
        },
        "jumpsub": {
            "v": 10,
            "d": "Base fee of the JUMPSUB opcode"
        }
    },
    "vm": {},
    "pow": {}
}

},{}],19:[function(require,module,exports){
module.exports={
    "name": "EIP-2537",
    "number": 2537,
    "comment": "BLS12-381 precompiles",
    "url": "https://eips.ethereum.org/EIPS/eip-2537",
    "status": "Draft",
    "minimumHardfork": "chainstart",
    "gasConfig": {},
    "gasPrices": {
        "Bls12381G1AddGas": {
            "v": 600,
            "d": "Gas cost of a single BLS12-381 G1 addition precompile-call"
        },
        "Bls12381G1MulGas": {
            "v": 12000,
            "d": "Gas cost of a single BLS12-381 G1 multiplication precompile-call"
        },
        "Bls12381G2AddGas": {
            "v": 4500,
            "d": "Gas cost of a single BLS12-381 G2 addition precompile-call"
        },
        "Bls12381G2MulGas": {
            "v": 55000,
            "d": "Gas cost of a single BLS12-381 G2 multiplication precompile-call"
        },
        "Bls12381PairingBaseGas": {
            "v": 115000,
            "d": "Base gas cost of BLS12-381 pairing check"
        },
        "Bls12381PairingPerPairGas": {
            "v": 23000,
            "d": "Per-pair gas cost of BLS12-381 pairing check"
        },
        "Bls12381MapG1Gas": {
            "v": 5500,
            "d": "Gas cost of BLS12-381 map field element to G1"
        },
        "Bls12381MapG2Gas": {
            "v": 110000,
            "d": "Gas cost of BLS12-381 map field element to G2"
        },
        "Bls12381MultiExpGasDiscount": {
            "v": [
                [1, 1200],
                [2, 888],
                [3, 764],
                [4, 641],
                [5, 594],
                [6, 547],
                [7, 500],
                [8, 453],
                [9, 438],
                [10, 423],
                [11, 408],
                [12, 394],
                [13, 379],
                [14, 364],
                [15, 349],
                [16, 334],
                [17, 330],
                [18, 326],
                [19, 322],
                [20, 318],
                [21, 314],
                [22, 310],
                [23, 306],
                [24, 302],
                [25, 298],
                [26, 294],
                [27, 289],
                [28, 285],
                [29, 281],
                [30, 277],
                [31, 273],
                [32, 269],
                [33, 268],
                [34, 266],
                [35, 265],
                [36, 263],
                [37, 262],
                [38, 260],
                [39, 259],
                [40, 257],
                [41, 256],
                [42, 254],
                [43, 253],
                [44, 251],
                [45, 250],
                [46, 248],
                [47, 247],
                [48, 245],
                [49, 244],
                [50, 242],
                [51, 241],
                [52, 239],
                [53, 238],
                [54, 236],
                [55, 235],
                [56, 233],
                [57, 232],
                [58, 231],
                [59, 229],
                [60, 228],
                [61, 226],
                [62, 225],
                [63, 223],
                [64, 222],
                [65, 221],
                [66, 220],
                [67, 219],
                [68, 219],
                [69, 218],
                [70, 217],
                [71, 216],
                [72, 216],
                [73, 215],
                [74, 214],
                [75, 213],
                [76, 213],
                [77, 212],
                [78, 211],
                [79, 211],
                [80, 210],
                [81, 209],
                [82, 208],
                [83, 208],
                [84, 207],
                [85, 206],
                [86, 205],
                [87, 205],
                [88, 204],
                [89, 203],
                [90, 202],
                [91, 202],
                [92, 201],
                [93, 200],
                [94, 199],
                [95, 199],
                [96, 198],
                [97, 197],
                [98, 196],
                [99, 196],
                [100, 195],
                [101, 194],
                [102, 193],
                [103, 193],
                [104, 192],
                [105, 191],
                [106, 191],
                [107, 190],
                [108, 189],
                [109, 188],
                [110, 188],
                [111, 187],
                [112, 186],
                [113, 185],
                [114, 185],
                [115, 184],
                [116, 183],
                [117, 182],
                [118, 182],
                [119, 181],
                [120, 180],
                [121, 179],
                [122, 179],
                [123, 178],
                [124, 177],
                [125, 176],
                [126, 176],
                [127, 175],
                [128, 174]
            ],
            "d": "Discount gas costs of calls to the MultiExp precompiles with `k` (point, scalar) pair"
        }
    },
    "vm": {},
    "pow": {}
}

},{}],20:[function(require,module,exports){
module.exports={
    "name": "EIP-2565",
    "number": 2565,
    "comment": "ModExp gas cost",
    "url": "https://eips.ethereum.org/EIPS/eip-2565",
    "status": "Final",
    "minimumHardfork": "byzantium",
    "gasConfig": {},
    "gasPrices": {
        "modexpGquaddivisor": {
            "v": 3,
            "d": "Gquaddivisor from modexp precompile for gas calculation"
        }
    },
    "vm": {},
    "pow": {}
}

},{}],21:[function(require,module,exports){
module.exports={
    "name": "EIP-2718",
    "comment": "Typed Transaction Envelope",
    "url": "https://eips.ethereum.org/EIPS/eip-2718",
    "status": "Final",
    "minimumHardfork": "chainstart",
    "gasConfig": {},
    "gasPrices": {},
    "vm": {},
    "pow": {}
}

},{}],22:[function(require,module,exports){
module.exports={
    "name": "EIP-2929",
    "comment": "Gas cost increases for state access opcodes",
    "url": "https://eips.ethereum.org/EIPS/eip-2929",
    "status": "Final",
    "minimumHardfork": "chainstart",
    "gasConfig": {},
    "gasPrices": {
        "coldsload": {
            "v": 2100,
            "d": "Gas cost of the first read of storage from a given location (per transaction)"
        },
        "coldaccountaccess": {
            "v": 2600,
            "d": "Gas cost of the first read of a given address (per transaction)"
        },
        "warmstorageread": {
            "v": 100,
            "d": "Gas cost of reading storage locations which have already loaded 'cold'"
        },
        "sstoreCleanGasEIP2200": {
            "v": 2900,
            "d": "Once per SSTORE operation from clean non-zero to something else"
        },
        "sstoreNoopGasEIP2200": {
            "v": 100,
            "d": "Once per SSTORE operation if the value doesn't change"
        },
        "sstoreDirtyGasEIP2200": {
            "v": 100,
            "d": "Once per SSTORE operation if a dirty value is changed"
        },
        "sstoreInitRefundEIP2200": {
            "v": 19900,
            "d": "Once per SSTORE operation for resetting to the original zero value"
        },
        "sstoreCleanRefundEIP2200": {
            "v": 4900,
            "d": "Once per SSTORE operation for resetting to the original non-zero value"
        },
        "call": {
            "v": 0,
            "d": "Base fee of the CALL opcode"
        },
        "callcode": {
            "v": 0,
            "d": "Base fee of the CALLCODE opcode"
        },
        "delegatecall": {
            "v": 0,
            "d": "Base fee of the DELEGATECALL opcode"
        },
        "staticcall": {
            "v": 0,
            "d": "Base fee of the STATICCALL opcode"
        },
        "balance": {
            "v": 0,
            "d": "Base fee of the BALANCE opcode"
        },
        "extcodesize": {
            "v": 0,
            "d": "Base fee of the EXTCODESIZE opcode"
        },
        "extcodecopy": {
            "v": 0,
            "d": "Base fee of the EXTCODECOPY opcode"
        },
        "extcodehash": {
            "v": 0,
            "d": "Base fee of the EXTCODEHASH opcode"
        },
        "sload": {
            "v": 0,
            "d": "Base fee of the SLOAD opcode"
        },
        "sstore": {
            "v": 0,
            "d": "Base fee of the SSTORE opcode"
        }
    },
    "vm": {},
    "pow": {}
}

},{}],23:[function(require,module,exports){
module.exports={
    "name": "EIP-2930",
    "comment": "Optional access lists",
    "url": "https://eips.ethereum.org/EIPS/eip-2930",
    "status": "Final",
    "minimumHardfork": "istanbul",
    "requiredEIPs": [2718, 2929],
    "gasConfig": {},
    "gasPrices": {
        "accessListStorageKeyCost": {
            "v": 1900,
            "d": "Gas cost per storage key in an Access List transaction"
        },
        "accessListAddressCost": {
            "v": 2400,
            "d": "Gas cost per storage key in an Access List transaction"
        }
    },
    "vm": {},
    "pow": {}
}

},{}],24:[function(require,module,exports){
module.exports={
    "name": "EIP-3074",
    "number": 3074,
    "comment": "AUTH and AUTHCALL opcodes",
    "url": "https://eips.ethereum.org/EIPS/eip-3074",
    "status": "Review",
    "minimumHardfork": "london",
    "gasConfig": {},
    "gasPrices": {
        "auth": {
            "v": 3100,
            "d": "Gas cost of the AUTH opcode"
        },
        "authcall": {
            "v": 0,
            "d": "Gas cost of the AUTHCALL opcode"
        },
        "authcallValueTransfer": {
            "v": 6700,
            "d": "Paid for CALL when the value transfer is non-zero"
        }
    },
    "vm": {},
    "pow": {}
}

},{}],25:[function(require,module,exports){
module.exports={
    "name": "EIP-3198",
    "number": 3198,
    "comment": "BASEFEE opcode",
    "url": "https://eips.ethereum.org/EIPS/eip-3198",
    "status": "Final",
    "minimumHardfork": "london",
    "gasConfig": {},
    "gasPrices": {
        "basefee": {
            "v": 2,
            "d": "Gas cost of the BASEFEE opcode"
        }
    },
    "vm": {},
    "pow": {}
}

},{}],26:[function(require,module,exports){
module.exports={
    "name": "EIP-3529",
    "comment": "Reduction in refunds",
    "url": "https://eips.ethereum.org/EIPS/eip-3529",
    "status": "Final",
    "minimumHardfork": "berlin",
    "requiredEIPs": [2929],
    "gasConfig": {
        "maxRefundQuotient": {
            "v": 5,
            "d": "Maximum refund quotient; max tx refund is min(tx.gasUsed/maxRefundQuotient, tx.gasRefund)"
        }
    },
    "gasPrices": {
        "selfdestructRefund": {
            "v": 0,
            "d": "Refunded following a selfdestruct operation"
        },
        "sstoreClearRefundEIP2200": {
            "v": 4800,
            "d": "Once per SSTORE operation for clearing an originally existing storage slot"
        }
    },
    "vm": {},
    "pow": {}
}

},{}],27:[function(require,module,exports){
module.exports={
    "name": "EIP-3540",
    "number": 3540,
    "comment": "EVM Object Format (EOF) v1",
    "url": "https://eips.ethereum.org/EIPS/eip-3540",
    "status": "Review",
    "minimumHardfork": "london",
    "requiredEIPs": [3541],
    "gasConfig": {},
    "gasPrices": {},
    "vm": {},
    "pow": {}
}

},{}],28:[function(require,module,exports){
module.exports={
    "name": "EIP-3541",
    "comment": "Reject new contracts starting with the 0xEF byte",
    "url": "https://eips.ethereum.org/EIPS/eip-3541",
    "status": "Final",
    "minimumHardfork": "berlin",
    "requiredEIPs": [],
    "gasConfig": {},
    "gasPrices": {},
    "vm": {},
    "pow": {}
}

},{}],29:[function(require,module,exports){
module.exports={
    "name": "EIP-3554",
    "comment": "Reduction in refunds",
    "url": "Difficulty Bomb Delay to December 1st 2021",
    "status": "Final",
    "minimumHardfork": "muirGlacier",
    "requiredEIPs": [],
    "gasConfig": {},
    "gasPrices": {},
    "vm": {},
    "pow": {
        "difficultyBombDelay": {
            "v": 9500000,
            "d": "the amount of blocks to delay the difficulty bomb with"
        }
    }
}

},{}],30:[function(require,module,exports){
module.exports={
    "name": "EIP-3607",
    "number": 3607,
    "comment": "Reject transactions from senders with deployed code",
    "url": "https://eips.ethereum.org/EIPS/eip-3607",
    "status": "Final",
    "minimumHardfork": "chainstart",
    "requiredEIPs": [],
    "gasConfig": {},
    "gasPrices": {},
    "vm": {},
    "pow": {}
}

},{}],31:[function(require,module,exports){
module.exports={
    "name": "EIP-3651",
    "number": 3198,
    "comment": "Warm COINBASE",
    "url": "https://eips.ethereum.org/EIPS/eip-3651",
    "status": "Review",
    "minimumHardfork": "london",
    "requiredEIPs": [2929],
    "gasConfig": {},
    "gasPrices": {},
    "vm": {},
    "pow": {}
}

},{}],32:[function(require,module,exports){
module.exports={
    "name": "EIP-3670",
    "number": 3670,
    "comment": "EOF - Code Validation",
    "url": "https://eips.ethereum.org/EIPS/eip-3670",
    "status": "Review",
    "minimumHardfork": "london",
    "requiredEIPs": [3540],
    "gasConfig": {},
    "gasPrices": {},
    "vm": {},
    "pow": {}
}

},{}],33:[function(require,module,exports){
module.exports={
    "name": "EIP-3675",
    "number": 3675,
    "comment": "Upgrade consensus to Proof-of-Stake",
    "url": "https://eips.ethereum.org/EIPS/eip-3675",
    "status": "Review",
    "minimumHardfork": "london",
    "requiredEIPs": [],
    "gasConfig": {},
    "gasPrices": {},
    "vm": {},
    "pow": {}
}

},{}],34:[function(require,module,exports){
module.exports={
    "name": "EIP-3855",
    "number": 3855,
    "comment": "PUSH0 instruction",
    "url": "https://eips.ethereum.org/EIPS/eip-3855",
    "status": "Review",
    "minimumHardfork": "chainstart",
    "requiredEIPs": [],
    "gasConfig": {},
    "gasPrices": {
        "push0": {
            "v": 2,
            "d": "Base fee of the PUSH0 opcode"
        }
    },
    "vm": {},
    "pow": {}
}

},{}],35:[function(require,module,exports){
module.exports={
    "name": "EIP-3860",
    "number": 3860,
    "comment": "Limit and meter initcode",
    "url": "https://eips.ethereum.org/EIPS/eip-3860",
    "status": "Review",
    "minimumHardfork": "spuriousDragon",
    "requiredEIPs": [],
    "gasConfig": {},
    "gasPrices": {
        "initCodeWordCost": {
            "v": 2,
            "d": "Gas to pay for each word (32 bytes) of initcode when creating a contract"
        }
    },
    "vm": {
        "maxInitCodeSize": {
            "v": 49152,
            "d": "Maximum length of initialization code when creating a contract"
        }
    },
    "pow": {}
}

},{}],36:[function(require,module,exports){
module.exports={
    "name": "EIP-4345",
    "number": 4345,
    "comment": "Difficulty Bomb Delay to June 2022",
    "url": "https://eips.ethereum.org/EIPS/eip-4345",
    "status": "Final",
    "minimumHardfork": "london",
    "gasConfig": {},
    "gasPrices": {},
    "vm": {},
    "pow": {
        "difficultyBombDelay": {
            "v": 10700000,
            "d": "the amount of blocks to delay the difficulty bomb with"
        }
    }
}

},{}],37:[function(require,module,exports){
module.exports={
    "name": "EIP-4399",
    "number": 4399,
    "comment": "Supplant DIFFICULTY opcode with PREVRANDAO",
    "url": "https://eips.ethereum.org/EIPS/eip-4399",
    "status": "Review",
    "minimumHardfork": "london",
    "requiredEIPs": [],
    "gasConfig": {},
    "gasPrices": {},
    "vm": {},
    "pow": {}
}

},{}],38:[function(require,module,exports){
module.exports={
    "name": "EIP-5133",
    "number": 5133,
    "comment": "Delaying Difficulty Bomb to mid-September 2022",
    "url": "https://eips.ethereum.org/EIPS/eip-5133",
    "status": "Draft",
    "minimumHardfork": "grayGlacier",
    "gasConfig": {},
    "gasPrices": {},
    "vm": {},
    "pow": {
        "difficultyBombDelay": {
            "v": 11400000,
            "d": "the amount of blocks to delay the difficulty bomb with"
        }
    }
}

},{}],39:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.EIPs = void 0;
exports.EIPs = {
    1153: require('./1153.json'),
    1559: require('./1559.json'),
    2315: require('./2315.json'),
    2537: require('./2537.json'),
    2565: require('./2565.json'),
    2718: require('./2718.json'),
    2929: require('./2929.json'),
    2930: require('./2930.json'),
    3074: require('./3074.json'),
    3198: require('./3198.json'),
    3529: require('./3529.json'),
    3540: require('./3540.json'),
    3541: require('./3541.json'),
    3554: require('./3554.json'),
    3607: require('./3607.json'),
    3651: require('./3651.json'),
    3670: require('./3670.json'),
    3675: require('./3675.json'),
    3855: require('./3855.json'),
    3860: require('./3860.json'),
    4345: require('./4345.json'),
    4399: require('./4399.json'),
    5133: require('./5133.json'),
};

},{"./1153.json":16,"./1559.json":17,"./2315.json":18,"./2537.json":19,"./2565.json":20,"./2718.json":21,"./2929.json":22,"./2930.json":23,"./3074.json":24,"./3198.json":25,"./3529.json":26,"./3540.json":27,"./3541.json":28,"./3554.json":29,"./3607.json":30,"./3651.json":31,"./3670.json":32,"./3675.json":33,"./3855.json":34,"./3860.json":35,"./4345.json":36,"./4399.json":37,"./5133.json":38}],40:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.CustomChain = exports.ConsensusAlgorithm = exports.ConsensusType = exports.Hardfork = exports.Chain = void 0;
var Chain;
(function (Chain) {
    Chain[Chain["Mainnet"] = 1] = "Mainnet";
    Chain[Chain["Ropsten"] = 3] = "Ropsten";
    Chain[Chain["Rinkeby"] = 4] = "Rinkeby";
    Chain[Chain["Goerli"] = 5] = "Goerli";
    Chain[Chain["Sepolia"] = 11155111] = "Sepolia";
})(Chain = exports.Chain || (exports.Chain = {}));
var Hardfork;
(function (Hardfork) {
    Hardfork["Chainstart"] = "chainstart";
    Hardfork["Homestead"] = "homestead";
    Hardfork["Dao"] = "dao";
    Hardfork["TangerineWhistle"] = "tangerineWhistle";
    Hardfork["SpuriousDragon"] = "spuriousDragon";
    Hardfork["Byzantium"] = "byzantium";
    Hardfork["Constantinople"] = "constantinople";
    Hardfork["Petersburg"] = "petersburg";
    Hardfork["Istanbul"] = "istanbul";
    Hardfork["MuirGlacier"] = "muirGlacier";
    Hardfork["Berlin"] = "berlin";
    Hardfork["London"] = "london";
    Hardfork["ArrowGlacier"] = "arrowGlacier";
    Hardfork["GrayGlacier"] = "grayGlacier";
    Hardfork["MergeForkIdTransition"] = "mergeForkIdTransition";
    Hardfork["Merge"] = "merge";
    Hardfork["Shanghai"] = "shanghai";
})(Hardfork = exports.Hardfork || (exports.Hardfork = {}));
var ConsensusType;
(function (ConsensusType) {
    ConsensusType["ProofOfStake"] = "pos";
    ConsensusType["ProofOfWork"] = "pow";
    ConsensusType["ProofOfAuthority"] = "poa";
})(ConsensusType = exports.ConsensusType || (exports.ConsensusType = {}));
var ConsensusAlgorithm;
(function (ConsensusAlgorithm) {
    ConsensusAlgorithm["Ethash"] = "ethash";
    ConsensusAlgorithm["Clique"] = "clique";
    ConsensusAlgorithm["Casper"] = "casper";
})(ConsensusAlgorithm = exports.ConsensusAlgorithm || (exports.ConsensusAlgorithm = {}));
var CustomChain;
(function (CustomChain) {
    /**
     * Polygon (Matic) Mainnet
     *
     * - [Documentation](https://docs.matic.network/docs/develop/network-details/network)
     */
    CustomChain["PolygonMainnet"] = "polygon-mainnet";
    /**
     * Polygon (Matic) Mumbai Testnet
     *
     * - [Documentation](https://docs.matic.network/docs/develop/network-details/network)
     */
    CustomChain["PolygonMumbai"] = "polygon-mumbai";
    /**
     * Arbitrum Rinkeby Testnet
     *
     * - [Documentation](https://developer.offchainlabs.com/docs/public_testnet)
     */
    CustomChain["ArbitrumRinkebyTestnet"] = "arbitrum-rinkeby-testnet";
    /**
     * xDai EVM sidechain with a native stable token
     *
     * - [Documentation](https://www.xdaichain.com/)
     */
    CustomChain["xDaiChain"] = "x-dai-chain";
    /**
     * Optimistic Kovan - testnet for Optimism roll-up
     *
     * - [Documentation](https://community.optimism.io/docs/developers/tutorials.html)
     */
    CustomChain["OptimisticKovan"] = "optimistic-kovan";
    /**
     * Optimistic Ethereum - mainnet for Optimism roll-up
     *
     * - [Documentation](https://community.optimism.io/docs/developers/tutorials.html)
     */
    CustomChain["OptimisticEthereum"] = "optimistic-ethereum";
})(CustomChain = exports.CustomChain || (exports.CustomChain = {}));

},{}],41:[function(require,module,exports){
module.exports={
    "name": "arrowGlacier",
    "comment": "HF to delay the difficulty bomb",
    "url": "https://github.com/ethereum/execution-specs/blob/master/network-upgrades/mainnet-upgrades/arrow-glacier.md",
    "status": "Final",
    "eips": [4345],
    "gasConfig": {},
    "gasPrices": {},
    "vm": {},
    "pow": {}
}

},{}],42:[function(require,module,exports){
module.exports={
    "name": "berlin",
    "comment": "HF targeted for July 2020 following the Muir Glacier HF",
    "url": "https://eips.ethereum.org/EIPS/eip-2070",
    "status": "Final",
    "eips": [2565, 2929, 2718, 2930]
}

},{}],43:[function(require,module,exports){
module.exports={
    "name": "byzantium",
    "comment": "Hardfork with new precompiles, instructions and other protocol changes",
    "url": "https://eips.ethereum.org/EIPS/eip-609",
    "status": "Final",
    "gasConfig": {},
    "gasPrices": {
        "modexpGquaddivisor": {
            "v": 20,
            "d": "Gquaddivisor from modexp precompile for gas calculation"
        },
        "ecAdd": {
            "v": 500,
            "d": "Gas costs for curve addition precompile"
        },
        "ecMul": {
            "v": 40000,
            "d": "Gas costs for curve multiplication precompile"
        },
        "ecPairing": {
            "v": 100000,
            "d": "Base gas costs for curve pairing precompile"
        },
        "ecPairingWord": {
            "v": 80000,
            "d": "Gas costs regarding curve pairing precompile input length"
        },
        "revert": {
            "v": 0,
            "d": "Base fee of the REVERT opcode"
        },
        "staticcall": {
            "v": 700,
            "d": "Base fee of the STATICCALL opcode"
        },
        "returndatasize": {
            "v": 2,
            "d": "Base fee of the RETURNDATASIZE opcode"
        },
        "returndatacopy": {
            "v": 3,
            "d": "Base fee of the RETURNDATACOPY opcode"
        }
    },
    "vm": {},
    "pow": {
        "minerReward": {
            "v": "3000000000000000000",
            "d": "the amount a miner get rewarded for mining a block"
        },
        "difficultyBombDelay": {
            "v": 3000000,
            "d": "the amount of blocks to delay the difficulty bomb with"
        }
    }
}

},{}],44:[function(require,module,exports){
module.exports={
    "name": "chainstart",
    "comment": "Start of the Ethereum main chain",
    "url": "",
    "status": "",
    "gasConfig": {
        "minGasLimit": {
            "v": 5000,
            "d": "Minimum the gas limit may ever be"
        },
        "gasLimitBoundDivisor": {
            "v": 1024,
            "d": "The bound divisor of the gas limit, used in update calculations"
        },
        "maxRefundQuotient": {
            "v": 2,
            "d": "Maximum refund quotient; max tx refund is min(tx.gasUsed/maxRefundQuotient, tx.gasRefund)"
        }
    },
    "gasPrices": {
        "base": {
            "v": 2,
            "d": "Gas base cost, used e.g. for ChainID opcode (Istanbul)"
        },
        "tierStep": {
            "v": [0, 2, 3, 5, 8, 10, 20],
            "d": "Once per operation, for a selection of them"
        },
        "exp": {
            "v": 10,
            "d": "Base fee of the EXP opcode"
        },
        "expByte": {
            "v": 10,
            "d": "Times ceil(log256(exponent)) for the EXP instruction"
        },
        "sha3": {
            "v": 30,
            "d": "Base fee of the SHA3 opcode"
        },
        "sha3Word": {
            "v": 6,
            "d": "Once per word of the SHA3 operation's data"
        },
        "sload": {
            "v": 50,
            "d": "Base fee of the SLOAD opcode"
        },
        "sstoreSet": {
            "v": 20000,
            "d": "Once per SSTORE operation if the zeroness changes from zero"
        },
        "sstoreReset": {
            "v": 5000,
            "d": "Once per SSTORE operation if the zeroness does not change from zero"
        },
        "sstoreRefund": {
            "v": 15000,
            "d": "Once per SSTORE operation if the zeroness changes to zero"
        },
        "jumpdest": {
            "v": 1,
            "d": "Base fee of the JUMPDEST opcode"
        },
        "log": {
            "v": 375,
            "d": "Base fee of the LOG opcode"
        },
        "logData": {
            "v": 8,
            "d": "Per byte in a LOG* operation's data"
        },
        "logTopic": {
            "v": 375,
            "d": "Multiplied by the * of the LOG*, per LOG transaction. e.g. LOG0 incurs 0 * c_txLogTopicGas, LOG4 incurs 4 * c_txLogTopicGas"
        },
        "create": {
            "v": 32000,
            "d": "Base fee of the CREATE opcode"
        },
        "call": {
            "v": 40,
            "d": "Base fee of the CALL opcode"
        },
        "callStipend": {
            "v": 2300,
            "d": "Free gas given at beginning of call"
        },
        "callValueTransfer": {
            "v": 9000,
            "d": "Paid for CALL when the value transfor is non-zero"
        },
        "callNewAccount": {
            "v": 25000,
            "d": "Paid for CALL when the destination address didn't exist prior"
        },
        "selfdestructRefund": {
            "v": 24000,
            "d": "Refunded following a selfdestruct operation"
        },
        "memory": {
            "v": 3,
            "d": "Times the address of the (highest referenced byte in memory + 1). NOTE: referencing happens on read, write and in instructions such as RETURN and CALL"
        },
        "quadCoeffDiv": {
            "v": 512,
            "d": "Divisor for the quadratic particle of the memory cost equation"
        },
        "createData": {
            "v": 200,
            "d": ""
        },
        "tx": {
            "v": 21000,
            "d": "Per transaction. NOTE: Not payable on data of calls between transactions"
        },
        "txCreation": {
            "v": 32000,
            "d": "The cost of creating a contract via tx"
        },
        "txDataZero": {
            "v": 4,
            "d": "Per byte of data attached to a transaction that equals zero. NOTE: Not payable on data of calls between transactions"
        },
        "txDataNonZero": {
            "v": 68,
            "d": "Per byte of data attached to a transaction that is not equal to zero. NOTE: Not payable on data of calls between transactions"
        },
        "copy": {
            "v": 3,
            "d": "Multiplied by the number of 32-byte words that are copied (round up) for any *COPY operation and added"
        },
        "ecRecover": {
            "v": 3000,
            "d": ""
        },
        "sha256": {
            "v": 60,
            "d": ""
        },
        "sha256Word": {
            "v": 12,
            "d": ""
        },
        "ripemd160": {
            "v": 600,
            "d": ""
        },
        "ripemd160Word": {
            "v": 120,
            "d": ""
        },
        "identity": {
            "v": 15,
            "d": ""
        },
        "identityWord": {
            "v": 3,
            "d": ""
        },
        "stop": {
            "v": 0,
            "d": "Base fee of the STOP opcode"
        },
        "add": {
            "v": 3,
            "d": "Base fee of the ADD opcode"
        },
        "mul": {
            "v": 5,
            "d": "Base fee of the MUL opcode"
        },
        "sub": {
            "v": 3,
            "d": "Base fee of the SUB opcode"
        },
        "div": {
            "v": 5,
            "d": "Base fee of the DIV opcode"
        },
        "sdiv": {
            "v": 5,
            "d": "Base fee of the SDIV opcode"
        },
        "mod": {
            "v": 5,
            "d": "Base fee of the MOD opcode"
        },
        "smod": {
            "v": 5,
            "d": "Base fee of the SMOD opcode"
        },
        "addmod": {
            "v": 8,
            "d": "Base fee of the ADDMOD opcode"
        },
        "mulmod": {
            "v": 8,
            "d": "Base fee of the MULMOD opcode"
        },
        "signextend": {
            "v": 5,
            "d": "Base fee of the SIGNEXTEND opcode"
        },
        "lt": {
            "v": 3,
            "d": "Base fee of the LT opcode"
        },
        "gt": {
            "v": 3,
            "d": "Base fee of the GT opcode"
        },
        "slt": {
            "v": 3,
            "d": "Base fee of the SLT opcode"
        },
        "sgt": {
            "v": 3,
            "d": "Base fee of the SGT opcode"
        },
        "eq": {
            "v": 3,
            "d": "Base fee of the EQ opcode"
        },
        "iszero": {
            "v": 3,
            "d": "Base fee of the ISZERO opcode"
        },
        "and": {
            "v": 3,
            "d": "Base fee of the AND opcode"
        },
        "or": {
            "v": 3,
            "d": "Base fee of the OR opcode"
        },
        "xor": {
            "v": 3,
            "d": "Base fee of the XOR opcode"
        },
        "not": {
            "v": 3,
            "d": "Base fee of the NOT opcode"
        },
        "byte": {
            "v": 3,
            "d": "Base fee of the BYTE opcode"
        },
        "address": {
            "v": 2,
            "d": "Base fee of the ADDRESS opcode"
        },
        "balance": {
            "v": 20,
            "d": "Base fee of the BALANCE opcode"
        },
        "origin": {
            "v": 2,
            "d": "Base fee of the ORIGIN opcode"
        },
        "caller": {
            "v": 2,
            "d": "Base fee of the CALLER opcode"
        },
        "callvalue": {
            "v": 2,
            "d": "Base fee of the CALLVALUE opcode"
        },
        "calldataload": {
            "v": 3,
            "d": "Base fee of the CALLDATALOAD opcode"
        },
        "calldatasize": {
            "v": 2,
            "d": "Base fee of the CALLDATASIZE opcode"
        },
        "calldatacopy": {
            "v": 3,
            "d": "Base fee of the CALLDATACOPY opcode"
        },
        "codesize": {
            "v": 2,
            "d": "Base fee of the CODESIZE opcode"
        },
        "codecopy": {
            "v": 3,
            "d": "Base fee of the CODECOPY opcode"
        },
        "gasprice": {
            "v": 2,
            "d": "Base fee of the GASPRICE opcode"
        },
        "extcodesize": {
            "v": 20,
            "d": "Base fee of the EXTCODESIZE opcode"
        },
        "extcodecopy": {
            "v": 20,
            "d": "Base fee of the EXTCODECOPY opcode"
        },
        "blockhash": {
            "v": 20,
            "d": "Base fee of the BLOCKHASH opcode"
        },
        "coinbase": {
            "v": 2,
            "d": "Base fee of the COINBASE opcode"
        },
        "timestamp": {
            "v": 2,
            "d": "Base fee of the TIMESTAMP opcode"
        },
        "number": {
            "v": 2,
            "d": "Base fee of the NUMBER opcode"
        },
        "difficulty": {
            "v": 2,
            "d": "Base fee of the DIFFICULTY opcode"
        },
        "gaslimit": {
            "v": 2,
            "d": "Base fee of the GASLIMIT opcode"
        },
        "pop": {
            "v": 2,
            "d": "Base fee of the POP opcode"
        },
        "mload": {
            "v": 3,
            "d": "Base fee of the MLOAD opcode"
        },
        "mstore": {
            "v": 3,
            "d": "Base fee of the MSTORE opcode"
        },
        "mstore8": {
            "v": 3,
            "d": "Base fee of the MSTORE8 opcode"
        },
        "sstore": {
            "v": 0,
            "d": "Base fee of the SSTORE opcode"
        },
        "jump": {
            "v": 8,
            "d": "Base fee of the JUMP opcode"
        },
        "jumpi": {
            "v": 10,
            "d": "Base fee of the JUMPI opcode"
        },
        "pc": {
            "v": 2,
            "d": "Base fee of the PC opcode"
        },
        "msize": {
            "v": 2,
            "d": "Base fee of the MSIZE opcode"
        },
        "gas": {
            "v": 2,
            "d": "Base fee of the GAS opcode"
        },
        "push": {
            "v": 3,
            "d": "Base fee of the PUSH opcode"
        },
        "dup": {
            "v": 3,
            "d": "Base fee of the DUP opcode"
        },
        "swap": {
            "v": 3,
            "d": "Base fee of the SWAP opcode"
        },
        "callcode": {
            "v": 40,
            "d": "Base fee of the CALLCODE opcode"
        },
        "return": {
            "v": 0,
            "d": "Base fee of the RETURN opcode"
        },
        "invalid": {
            "v": 0,
            "d": "Base fee of the INVALID opcode"
        },
        "selfdestruct": {
            "v": 0,
            "d": "Base fee of the SELFDESTRUCT opcode"
        }
    },
    "vm": {
        "stackLimit": {
            "v": 1024,
            "d": "Maximum size of VM stack allowed"
        },
        "callCreateDepth": {
            "v": 1024,
            "d": "Maximum depth of call/create stack"
        },
        "maxExtraDataSize": {
            "v": 32,
            "d": "Maximum size extra data may be after Genesis"
        }
    },
    "pow": {
        "minimumDifficulty": {
            "v": 131072,
            "d": "The minimum that the difficulty may ever be"
        },
        "difficultyBoundDivisor": {
            "v": 2048,
            "d": "The bound divisor of the difficulty, used in the update calculations"
        },
        "durationLimit": {
            "v": 13,
            "d": "The decision boundary on the blocktime duration used to determine whether difficulty should go up or not"
        },
        "epochDuration": {
            "v": 30000,
            "d": "Duration between proof-of-work epochs"
        },
        "timebombPeriod": {
            "v": 100000,
            "d": "Exponential difficulty timebomb period"
        },
        "minerReward": {
            "v": "5000000000000000000",
            "d": "the amount a miner get rewarded for mining a block"
        },
        "difficultyBombDelay": {
            "v": 0,
            "d": "the amount of blocks to delay the difficulty bomb with"
        }
    }
}

},{}],45:[function(require,module,exports){
module.exports={
    "name": "constantinople",
    "comment": "Postponed hardfork including EIP-1283 (SSTORE gas metering changes)",
    "url": "https://eips.ethereum.org/EIPS/eip-1013",
    "status": "Final",
    "gasConfig": {},
    "gasPrices": {
        "netSstoreNoopGas": {
            "v": 200,
            "d": "Once per SSTORE operation if the value doesn't change"
        },
        "netSstoreInitGas": {
            "v": 20000,
            "d": "Once per SSTORE operation from clean zero"
        },
        "netSstoreCleanGas": {
            "v": 5000,
            "d": "Once per SSTORE operation from clean non-zero"
        },
        "netSstoreDirtyGas": {
            "v": 200,
            "d": "Once per SSTORE operation from dirty"
        },
        "netSstoreClearRefund": {
            "v": 15000,
            "d": "Once per SSTORE operation for clearing an originally existing storage slot"
        },
        "netSstoreResetRefund": {
            "v": 4800,
            "d": "Once per SSTORE operation for resetting to the original non-zero value"
        },
        "netSstoreResetClearRefund": {
            "v": 19800,
            "d": "Once per SSTORE operation for resetting to the original zero value"
        },
        "shl": {
            "v": 3,
            "d": "Base fee of the SHL opcode"
        },
        "shr": {
            "v": 3,
            "d": "Base fee of the SHR opcode"
        },
        "sar": {
            "v": 3,
            "d": "Base fee of the SAR opcode"
        },
        "extcodehash": {
            "v": 400,
            "d": "Base fee of the EXTCODEHASH opcode"
        },
        "create2": {
            "v": 32000,
            "d": "Base fee of the CREATE2 opcode"
        }
    },
    "vm": {},
    "pow": {
        "minerReward": {
            "v": "2000000000000000000",
            "d": "The amount a miner gets rewarded for mining a block"
        },
        "difficultyBombDelay": {
            "v": 5000000,
            "d": "the amount of blocks to delay the difficulty bomb with"
        }
    }
}

},{}],46:[function(require,module,exports){
module.exports={
    "name": "dao",
    "comment": "DAO rescue hardfork",
    "url": "https://eips.ethereum.org/EIPS/eip-779",
    "status": "Final",
    "gasConfig": {},
    "gasPrices": {},
    "vm": {},
    "pow": {}
}

},{}],47:[function(require,module,exports){
module.exports={
    "name": "grayGlacier",
    "comment": "Delaying the difficulty bomb to Mid September 2022",
    "url": "https://github.com/ethereum/execution-specs/blob/master/network-upgrades/mainnet-upgrades/gray-glacier.md",
    "status": "Draft",
    "eips": [5133],
    "gasConfig": {},
    "gasPrices": {},
    "vm": {},
    "pow": {}
}

},{}],48:[function(require,module,exports){
module.exports={
    "name": "homestead",
    "comment": "Homestead hardfork with protocol and network changes",
    "url": "https://eips.ethereum.org/EIPS/eip-606",
    "status": "Final",
    "gasConfig": {},
    "gasPrices": {
        "delegatecall": {
            "v": 40,
            "d": "Base fee of the DELEGATECALL opcode"
        }
    },
    "vm": {},
    "pow": {}
}

},{}],49:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.hardforks = void 0;
exports.hardforks = [
    ['chainstart', require('./chainstart.json')],
    ['homestead', require('./homestead.json')],
    ['dao', require('./dao.json')],
    ['tangerineWhistle', require('./tangerineWhistle.json')],
    ['spuriousDragon', require('./spuriousDragon.json')],
    ['byzantium', require('./byzantium.json')],
    ['constantinople', require('./constantinople.json')],
    ['petersburg', require('./petersburg.json')],
    ['istanbul', require('./istanbul.json')],
    ['muirGlacier', require('./muirGlacier.json')],
    ['berlin', require('./berlin.json')],
    ['london', require('./london.json')],
    ['shanghai', require('./shanghai.json')],
    ['arrowGlacier', require('./arrowGlacier.json')],
    ['grayGlacier', require('./grayGlacier.json')],
    ['mergeForkIdTransition', require('./mergeForkIdTransition.json')],
    ['merge', require('./merge.json')],
];

},{"./arrowGlacier.json":41,"./berlin.json":42,"./byzantium.json":43,"./chainstart.json":44,"./constantinople.json":45,"./dao.json":46,"./grayGlacier.json":47,"./homestead.json":48,"./istanbul.json":50,"./london.json":51,"./merge.json":52,"./mergeForkIdTransition.json":53,"./muirGlacier.json":54,"./petersburg.json":55,"./shanghai.json":56,"./spuriousDragon.json":57,"./tangerineWhistle.json":58}],50:[function(require,module,exports){
module.exports={
    "name": "istanbul",
    "comment": "HF targeted for December 2019 following the Constantinople/Petersburg HF",
    "url": "https://eips.ethereum.org/EIPS/eip-1679",
    "status": "Final",
    "gasConfig": {},
    "gasPrices": {
        "blake2Round": {
            "v": 1,
            "d": "Gas cost per round for the Blake2 F precompile"
        },
        "ecAdd": {
            "v": 150,
            "d": "Gas costs for curve addition precompile"
        },
        "ecMul": {
            "v": 6000,
            "d": "Gas costs for curve multiplication precompile"
        },
        "ecPairing": {
            "v": 45000,
            "d": "Base gas costs for curve pairing precompile"
        },
        "ecPairingWord": {
            "v": 34000,
            "d": "Gas costs regarding curve pairing precompile input length"
        },
        "txDataNonZero": {
            "v": 16,
            "d": "Per byte of data attached to a transaction that is not equal to zero. NOTE: Not payable on data of calls between transactions"
        },
        "sstoreSentryGasEIP2200": {
            "v": 2300,
            "d": "Minimum gas required to be present for an SSTORE call, not consumed"
        },
        "sstoreNoopGasEIP2200": {
            "v": 800,
            "d": "Once per SSTORE operation if the value doesn't change"
        },
        "sstoreDirtyGasEIP2200": {
            "v": 800,
            "d": "Once per SSTORE operation if a dirty value is changed"
        },
        "sstoreInitGasEIP2200": {
            "v": 20000,
            "d": "Once per SSTORE operation from clean zero to non-zero"
        },
        "sstoreInitRefundEIP2200": {
            "v": 19200,
            "d": "Once per SSTORE operation for resetting to the original zero value"
        },
        "sstoreCleanGasEIP2200": {
            "v": 5000,
            "d": "Once per SSTORE operation from clean non-zero to something else"
        },
        "sstoreCleanRefundEIP2200": {
            "v": 4200,
            "d": "Once per SSTORE operation for resetting to the original non-zero value"
        },
        "sstoreClearRefundEIP2200": {
            "v": 15000,
            "d": "Once per SSTORE operation for clearing an originally existing storage slot"
        },
        "balance": {
            "v": 700,
            "d": "Base fee of the BALANCE opcode"
        },
        "extcodehash": {
            "v": 700,
            "d": "Base fee of the EXTCODEHASH opcode"
        },
        "chainid": {
            "v": 2,
            "d": "Base fee of the CHAINID opcode"
        },
        "selfbalance": {
            "v": 5,
            "d": "Base fee of the SELFBALANCE opcode"
        },
        "sload": {
            "v": 800,
            "d": "Base fee of the SLOAD opcode"
        }
    },
    "vm": {},
    "pow": {}
}

},{}],51:[function(require,module,exports){
module.exports={
    "name": "london",
    "comment": "HF targeted for July 2021 following the Berlin fork",
    "url": "https://github.com/ethereum/eth1.0-specs/blob/master/network-upgrades/mainnet-upgrades/london.md",
    "status": "Final",
    "eips": [1559, 3198, 3529, 3541]
}

},{}],52:[function(require,module,exports){
module.exports={
    "name": "merge",
    "comment": "Hardfork to upgrade the consensus mechanism to Proof-of-Stake",
    "url": "https://github.com/ethereum/execution-specs/blob/master/network-upgrades/mainnet-upgrades/merge.md",
    "status": "Draft",
    "consensus": {
        "type": "pos",
        "algorithm": "casper",
        "casper": {}
    },
    "eips": [3675, 4399]
}

},{}],53:[function(require,module,exports){
module.exports={
    "name": "mergeForkIdTransition",
    "comment": "Pre-merge hardfork to fork off non-upgraded clients",
    "url": "https://eips.ethereum.org/EIPS/eip-3675",
    "status": "Draft",
    "eips": []
}

},{}],54:[function(require,module,exports){
module.exports={
    "name": "muirGlacier",
    "comment": "HF to delay the difficulty bomb",
    "url": "https://eips.ethereum.org/EIPS/eip-2384",
    "status": "Final",
    "gasConfig": {},
    "gasPrices": {},
    "vm": {},
    "pow": {
        "difficultyBombDelay": {
            "v": 9000000,
            "d": "the amount of blocks to delay the difficulty bomb with"
        }
    }
}

},{}],55:[function(require,module,exports){
module.exports={
    "name": "petersburg",
    "comment": "Aka constantinopleFix, removes EIP-1283, activate together with or after constantinople",
    "url": "https://eips.ethereum.org/EIPS/eip-1716",
    "status": "Final",
    "gasConfig": {},
    "gasPrices": {
        "netSstoreNoopGas": {
            "v": null,
            "d": "Removed along EIP-1283"
        },
        "netSstoreInitGas": {
            "v": null,
            "d": "Removed along EIP-1283"
        },
        "netSstoreCleanGas": {
            "v": null,
            "d": "Removed along EIP-1283"
        },
        "netSstoreDirtyGas": {
            "v": null,
            "d": "Removed along EIP-1283"
        },
        "netSstoreClearRefund": {
            "v": null,
            "d": "Removed along EIP-1283"
        },
        "netSstoreResetRefund": {
            "v": null,
            "d": "Removed along EIP-1283"
        },
        "netSstoreResetClearRefund": {
            "v": null,
            "d": "Removed along EIP-1283"
        }
    },
    "vm": {},
    "pow": {}
}

},{}],56:[function(require,module,exports){
module.exports={
    "name": "shanghai",
    "comment": "Next feature hardfork after the merge hardfork",
    "url": "https://github.com/ethereum/pm/issues/356",
    "status": "Pre-Draft",
    "eips": []
}

},{}],57:[function(require,module,exports){
module.exports={
    "name": "spuriousDragon",
    "comment": "HF with EIPs for simple replay attack protection, EXP cost increase, state trie clearing, contract code size limit",
    "url": "https://eips.ethereum.org/EIPS/eip-607",
    "status": "Final",
    "gasConfig": {},
    "gasPrices": {
        "expByte": {
            "v": 50,
            "d": "Times ceil(log256(exponent)) for the EXP instruction"
        }
    },
    "vm": {
        "maxCodeSize": {
            "v": 24576,
            "d": "Maximum length of contract code"
        }
    },
    "pow": {}
}

},{}],58:[function(require,module,exports){
module.exports={
    "name": "tangerineWhistle",
    "comment": "Hardfork with gas cost changes for IO-heavy operations",
    "url": "https://eips.ethereum.org/EIPS/eip-608",
    "status": "Final",
    "gasConfig": {},
    "gasPrices": {
        "sload": {
            "v": 200,
            "d": "Once per SLOAD operation"
        },
        "call": {
            "v": 700,
            "d": "Once per CALL operation & message call transaction"
        },
        "extcodesize": {
            "v": 700,
            "d": "Base fee of the EXTCODESIZE opcode"
        },
        "extcodecopy": {
            "v": 700,
            "d": "Base fee of the EXTCODECOPY opcode"
        },
        "balance": {
            "v": 400,
            "d": "Base fee of the BALANCE opcode"
        },
        "delegatecall": {
            "v": 700,
            "d": "Base fee of the DELEGATECALL opcode"
        },
        "callcode": {
            "v": 700,
            "d": "Base fee of the CALLCODE opcode"
        },
        "selfdestruct": {
            "v": 5000,
            "d": "Base fee of the SELFDESTRUCT opcode"
        }
    },
    "vm": {},
    "pow": {}
}

},{}],59:[function(require,module,exports){
"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __exportStar = (this && this.__exportStar) || function(m, exports) {
    for (var p in m) if (p !== "default" && !Object.prototype.hasOwnProperty.call(exports, p)) __createBinding(exports, m, p);
};
Object.defineProperty(exports, "__esModule", { value: true });
__exportStar(require("./common"), exports);
__exportStar(require("./enums"), exports);
__exportStar(require("./types"), exports);

},{"./common":15,"./enums":40,"./types":60}],60:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });

},{}],61:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.keccak512 = exports.keccak384 = exports.keccak256 = exports.keccak224 = void 0;
const sha3_1 = require("@noble/hashes/sha3");
const utils_1 = require("./utils");
exports.keccak224 = (0, utils_1.wrapHash)(sha3_1.keccak_224);
exports.keccak256 = (() => {
    const k = (0, utils_1.wrapHash)(sha3_1.keccak_256);
    k.create = sha3_1.keccak_256.create;
    return k;
})();
exports.keccak384 = (0, utils_1.wrapHash)(sha3_1.keccak_384);
exports.keccak512 = (0, utils_1.wrapHash)(sha3_1.keccak_512);

},{"./utils":62,"@noble/hashes/sha3":81}],62:[function(require,module,exports){
"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.crypto = exports.wrapHash = exports.equalsBytes = exports.hexToBytes = exports.bytesToUtf8 = exports.utf8ToBytes = exports.createView = exports.concatBytes = exports.toHex = exports.bytesToHex = exports.assertBytes = exports.assertBool = void 0;
// buf.toString('hex') -> toHex(buf)
const _assert_1 = __importDefault(require("@noble/hashes/_assert"));
const utils_1 = require("@noble/hashes/utils");
const assertBool = _assert_1.default.bool;
exports.assertBool = assertBool;
const assertBytes = _assert_1.default.bytes;
exports.assertBytes = assertBytes;
var utils_2 = require("@noble/hashes/utils");
Object.defineProperty(exports, "bytesToHex", { enumerable: true, get: function () { return utils_2.bytesToHex; } });
Object.defineProperty(exports, "toHex", { enumerable: true, get: function () { return utils_2.bytesToHex; } });
Object.defineProperty(exports, "concatBytes", { enumerable: true, get: function () { return utils_2.concatBytes; } });
Object.defineProperty(exports, "createView", { enumerable: true, get: function () { return utils_2.createView; } });
Object.defineProperty(exports, "utf8ToBytes", { enumerable: true, get: function () { return utils_2.utf8ToBytes; } });
// buf.toString('utf8') -> bytesToUtf8(buf)
function bytesToUtf8(data) {
    if (!(data instanceof Uint8Array)) {
        throw new TypeError(`bytesToUtf8 expected Uint8Array, got ${typeof data}`);
    }
    return new TextDecoder().decode(data);
}
exports.bytesToUtf8 = bytesToUtf8;
function hexToBytes(data) {
    const sliced = data.startsWith("0x") ? data.substring(2) : data;
    return (0, utils_1.hexToBytes)(sliced);
}
exports.hexToBytes = hexToBytes;
// buf.equals(buf2) -> equalsBytes(buf, buf2)
function equalsBytes(a, b) {
    if (a.length !== b.length) {
        return false;
    }
    for (let i = 0; i < a.length; i++) {
        if (a[i] !== b[i]) {
            return false;
        }
    }
    return true;
}
exports.equalsBytes = equalsBytes;
// Internal utils
function wrapHash(hash) {
    return (msg) => {
        _assert_1.default.bytes(msg);
        return hash(msg);
    };
}
exports.wrapHash = wrapHash;
exports.crypto = (() => {
    const webCrypto = typeof self === "object" && "crypto" in self ? self.crypto : undefined;
    const nodeRequire = typeof module !== "undefined" &&
        typeof module.require === "function" &&
        module.require.bind(module);
    return {
        node: nodeRequire && !webCrypto ? nodeRequire("crypto") : undefined,
        web: webCrypto
    };
})();

},{"@noble/hashes/_assert":75,"@noble/hashes/utils":82}],63:[function(require,module,exports){
(function (Buffer){(function (){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.convertSlimAccount = exports.isZeroAddress = exports.zeroAddress = exports.importPublic = exports.privateToAddress = exports.privateToPublic = exports.publicToAddress = exports.pubToAddress = exports.isValidPublic = exports.isValidPrivate = exports.generateAddress2 = exports.generateAddress = exports.isValidChecksumAddress = exports.toChecksumAddress = exports.isValidAddress = exports.Account = void 0;
const rlp_1 = require("@ethereumjs/rlp");
const keccak_1 = require("ethereum-cryptography/keccak");
const secp256k1_1 = require("ethereum-cryptography/secp256k1");
const utils_1 = require("ethereum-cryptography/utils");
const bytes_1 = require("./bytes");
const constants_1 = require("./constants");
const helpers_1 = require("./helpers");
const internal_1 = require("./internal");
const _0n = BigInt(0);
class Account {
    /**
     * This constructor assigns and validates the values.
     * Use the static factory methods to assist in creating an Account from varying data types.
     */
    constructor(nonce = _0n, balance = _0n, storageRoot = constants_1.KECCAK256_RLP, codeHash = constants_1.KECCAK256_NULL) {
        this.nonce = nonce;
        this.balance = balance;
        this.storageRoot = storageRoot;
        this.codeHash = codeHash;
        this._validate();
    }
    static fromAccountData(accountData) {
        const { nonce, balance, storageRoot, codeHash } = accountData;
        return new Account(nonce !== undefined ? (0, bytes_1.bufferToBigInt)((0, bytes_1.toBuffer)(nonce)) : undefined, balance !== undefined ? (0, bytes_1.bufferToBigInt)((0, bytes_1.toBuffer)(balance)) : undefined, storageRoot !== undefined ? (0, bytes_1.toBuffer)(storageRoot) : undefined, codeHash !== undefined ? (0, bytes_1.toBuffer)(codeHash) : undefined);
    }
    static fromRlpSerializedAccount(serialized) {
        const values = (0, bytes_1.arrToBufArr)(rlp_1.RLP.decode(Uint8Array.from(serialized)));
        if (!Array.isArray(values)) {
            throw new Error('Invalid serialized account input. Must be array');
        }
        return this.fromValuesArray(values);
    }
    static fromValuesArray(values) {
        const [nonce, balance, storageRoot, codeHash] = values;
        return new Account((0, bytes_1.bufferToBigInt)(nonce), (0, bytes_1.bufferToBigInt)(balance), storageRoot, codeHash);
    }
    _validate() {
        if (this.nonce < _0n) {
            throw new Error('nonce must be greater than zero');
        }
        if (this.balance < _0n) {
            throw new Error('balance must be greater than zero');
        }
        if (this.storageRoot.length !== 32) {
            throw new Error('storageRoot must have a length of 32');
        }
        if (this.codeHash.length !== 32) {
            throw new Error('codeHash must have a length of 32');
        }
    }
    /**
     * Returns a Buffer Array of the raw Buffers for the account, in order.
     */
    raw() {
        return [
            (0, bytes_1.bigIntToUnpaddedBuffer)(this.nonce),
            (0, bytes_1.bigIntToUnpaddedBuffer)(this.balance),
            this.storageRoot,
            this.codeHash,
        ];
    }
    /**
     * Returns the RLP serialization of the account as a `Buffer`.
     */
    serialize() {
        return Buffer.from(rlp_1.RLP.encode((0, bytes_1.bufArrToArr)(this.raw())));
    }
    /**
     * Returns a `Boolean` determining if the account is a contract.
     */
    isContract() {
        return !this.codeHash.equals(constants_1.KECCAK256_NULL);
    }
    /**
     * Returns a `Boolean` determining if the account is empty complying to the definition of
     * account emptiness in [EIP-161](https://eips.ethereum.org/EIPS/eip-161):
     * "An account is considered empty when it has no code and zero nonce and zero balance."
     */
    isEmpty() {
        return this.balance === _0n && this.nonce === _0n && this.codeHash.equals(constants_1.KECCAK256_NULL);
    }
}
exports.Account = Account;
/**
 * Checks if the address is a valid. Accepts checksummed addresses too.
 */
const isValidAddress = function (hexAddress) {
    try {
        (0, helpers_1.assertIsString)(hexAddress);
    }
    catch (e) {
        return false;
    }
    return /^0x[0-9a-fA-F]{40}$/.test(hexAddress);
};
exports.isValidAddress = isValidAddress;
/**
 * Returns a checksummed address.
 *
 * If an eip1191ChainId is provided, the chainId will be included in the checksum calculation. This
 * has the effect of checksummed addresses for one chain having invalid checksums for others.
 * For more details see [EIP-1191](https://eips.ethereum.org/EIPS/eip-1191).
 *
 * WARNING: Checksums with and without the chainId will differ and the EIP-1191 checksum is not
 * backwards compatible to the original widely adopted checksum format standard introduced in
 * [EIP-55](https://eips.ethereum.org/EIPS/eip-55), so this will break in existing applications.
 * Usage of this EIP is therefore discouraged unless you have a very targeted use case.
 */
const toChecksumAddress = function (hexAddress, eip1191ChainId) {
    (0, helpers_1.assertIsHexString)(hexAddress);
    const address = (0, internal_1.stripHexPrefix)(hexAddress).toLowerCase();
    let prefix = '';
    if (eip1191ChainId !== undefined) {
        const chainId = (0, bytes_1.bufferToBigInt)((0, bytes_1.toBuffer)(eip1191ChainId));
        prefix = chainId.toString() + '0x';
    }
    const buf = Buffer.from(prefix + address, 'utf8');
    const hash = (0, utils_1.bytesToHex)((0, keccak_1.keccak256)(buf));
    let ret = '0x';
    for (let i = 0; i < address.length; i++) {
        if (parseInt(hash[i], 16) >= 8) {
            ret += address[i].toUpperCase();
        }
        else {
            ret += address[i];
        }
    }
    return ret;
};
exports.toChecksumAddress = toChecksumAddress;
/**
 * Checks if the address is a valid checksummed address.
 *
 * See toChecksumAddress' documentation for details about the eip1191ChainId parameter.
 */
const isValidChecksumAddress = function (hexAddress, eip1191ChainId) {
    return (0, exports.isValidAddress)(hexAddress) && (0, exports.toChecksumAddress)(hexAddress, eip1191ChainId) === hexAddress;
};
exports.isValidChecksumAddress = isValidChecksumAddress;
/**
 * Generates an address of a newly created contract.
 * @param from The address which is creating this new address
 * @param nonce The nonce of the from account
 */
const generateAddress = function (from, nonce) {
    (0, helpers_1.assertIsBuffer)(from);
    (0, helpers_1.assertIsBuffer)(nonce);
    if ((0, bytes_1.bufferToBigInt)(nonce) === BigInt(0)) {
        // in RLP we want to encode null in the case of zero nonce
        // read the RLP documentation for an answer if you dare
        return Buffer.from((0, keccak_1.keccak256)(rlp_1.RLP.encode((0, bytes_1.bufArrToArr)([from, null])))).slice(-20);
    }
    // Only take the lower 160bits of the hash
    return Buffer.from((0, keccak_1.keccak256)(rlp_1.RLP.encode((0, bytes_1.bufArrToArr)([from, nonce])))).slice(-20);
};
exports.generateAddress = generateAddress;
/**
 * Generates an address for a contract created using CREATE2.
 * @param from The address which is creating this new address
 * @param salt A salt
 * @param initCode The init code of the contract being created
 */
const generateAddress2 = function (from, salt, initCode) {
    (0, helpers_1.assertIsBuffer)(from);
    (0, helpers_1.assertIsBuffer)(salt);
    (0, helpers_1.assertIsBuffer)(initCode);
    if (from.length !== 20) {
        throw new Error('Expected from to be of length 20');
    }
    if (salt.length !== 32) {
        throw new Error('Expected salt to be of length 32');
    }
    const address = (0, keccak_1.keccak256)(Buffer.concat([Buffer.from('ff', 'hex'), from, salt, (0, keccak_1.keccak256)(initCode)]));
    return (0, bytes_1.toBuffer)(address).slice(-20);
};
exports.generateAddress2 = generateAddress2;
/**
 * Checks if the private key satisfies the rules of the curve secp256k1.
 */
const isValidPrivate = function (privateKey) {
    return secp256k1_1.utils.isValidPrivateKey(privateKey);
};
exports.isValidPrivate = isValidPrivate;
/**
 * Checks if the public key satisfies the rules of the curve secp256k1
 * and the requirements of Ethereum.
 * @param publicKey The two points of an uncompressed key, unless sanitize is enabled
 * @param sanitize Accept public keys in other formats
 */
const isValidPublic = function (publicKey, sanitize = false) {
    (0, helpers_1.assertIsBuffer)(publicKey);
    if (publicKey.length === 64) {
        // Convert to SEC1 for secp256k1
        // Automatically checks whether point is on curve
        try {
            secp256k1_1.Point.fromHex(Buffer.concat([Buffer.from([4]), publicKey]));
            return true;
        }
        catch (e) {
            return false;
        }
    }
    if (!sanitize) {
        return false;
    }
    try {
        secp256k1_1.Point.fromHex(publicKey);
        return true;
    }
    catch (e) {
        return false;
    }
};
exports.isValidPublic = isValidPublic;
/**
 * Returns the ethereum address of a given public key.
 * Accepts "Ethereum public keys" and SEC1 encoded keys.
 * @param pubKey The two points of an uncompressed key, unless sanitize is enabled
 * @param sanitize Accept public keys in other formats
 */
const pubToAddress = function (pubKey, sanitize = false) {
    (0, helpers_1.assertIsBuffer)(pubKey);
    if (sanitize && pubKey.length !== 64) {
        pubKey = Buffer.from(secp256k1_1.Point.fromHex(pubKey).toRawBytes(false).slice(1));
    }
    if (pubKey.length !== 64) {
        throw new Error('Expected pubKey to be of length 64');
    }
    // Only take the lower 160bits of the hash
    return Buffer.from((0, keccak_1.keccak256)(pubKey)).slice(-20);
};
exports.pubToAddress = pubToAddress;
exports.publicToAddress = exports.pubToAddress;
/**
 * Returns the ethereum public key of a given private key.
 * @param privateKey A private key must be 256 bits wide
 */
const privateToPublic = function (privateKey) {
    (0, helpers_1.assertIsBuffer)(privateKey);
    // skip the type flag and use the X, Y points
    return Buffer.from(secp256k1_1.Point.fromPrivateKey(privateKey).toRawBytes(false).slice(1));
};
exports.privateToPublic = privateToPublic;
/**
 * Returns the ethereum address of a given private key.
 * @param privateKey A private key must be 256 bits wide
 */
const privateToAddress = function (privateKey) {
    return (0, exports.publicToAddress)((0, exports.privateToPublic)(privateKey));
};
exports.privateToAddress = privateToAddress;
/**
 * Converts a public key to the Ethereum format.
 */
const importPublic = function (publicKey) {
    (0, helpers_1.assertIsBuffer)(publicKey);
    if (publicKey.length !== 64) {
        publicKey = Buffer.from(secp256k1_1.Point.fromHex(publicKey).toRawBytes(false).slice(1));
    }
    return publicKey;
};
exports.importPublic = importPublic;
/**
 * Returns the zero address.
 */
const zeroAddress = function () {
    const addressLength = 20;
    const addr = (0, bytes_1.zeros)(addressLength);
    return (0, bytes_1.bufferToHex)(addr);
};
exports.zeroAddress = zeroAddress;
/**
 * Checks if a given address is the zero address.
 */
const isZeroAddress = function (hexAddress) {
    try {
        (0, helpers_1.assertIsString)(hexAddress);
    }
    catch (e) {
        return false;
    }
    const zeroAddr = (0, exports.zeroAddress)();
    return zeroAddr === hexAddress;
};
exports.isZeroAddress = isZeroAddress;
/**
 * Converts a slim account RLP to a normal account RLP
 */
function convertSlimAccount(body) {
    const cpy = [body[0], body[1], body[2], body[3]];
    if ((0, bytes_1.arrToBufArr)(body[2]).length === 0) {
        // StorageRoot
        cpy[2] = constants_1.KECCAK256_RLP;
    }
    if ((0, bytes_1.arrToBufArr)(body[3]).length === 0) {
        // CodeHash
        cpy[3] = constants_1.KECCAK256_NULL;
    }
    return (0, bytes_1.arrToBufArr)(rlp_1.RLP.encode(cpy));
}
exports.convertSlimAccount = convertSlimAccount;

}).call(this)}).call(this,require("buffer").Buffer)
},{"./bytes":65,"./constants":66,"./helpers":67,"./internal":69,"@ethereumjs/rlp":1,"buffer":89,"ethereum-cryptography/keccak":72,"ethereum-cryptography/secp256k1":73,"ethereum-cryptography/utils":74}],64:[function(require,module,exports){
(function (Buffer){(function (){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Address = void 0;
const account_1 = require("./account");
const bytes_1 = require("./bytes");
class Address {
    constructor(buf) {
        if (buf.length !== 20) {
            throw new Error('Invalid address length');
        }
        this.buf = buf;
    }
    /**
     * Returns the zero address.
     */
    static zero() {
        return new Address((0, bytes_1.zeros)(20));
    }
    /**
     * Returns an Address object from a hex-encoded string.
     * @param str - Hex-encoded address
     */
    static fromString(str) {
        if (!(0, account_1.isValidAddress)(str)) {
            throw new Error('Invalid address');
        }
        return new Address((0, bytes_1.toBuffer)(str));
    }
    /**
     * Returns an address for a given public key.
     * @param pubKey The two points of an uncompressed key
     */
    static fromPublicKey(pubKey) {
        if (!Buffer.isBuffer(pubKey)) {
            throw new Error('Public key should be Buffer');
        }
        const buf = (0, account_1.pubToAddress)(pubKey);
        return new Address(buf);
    }
    /**
     * Returns an address for a given private key.
     * @param privateKey A private key must be 256 bits wide
     */
    static fromPrivateKey(privateKey) {
        if (!Buffer.isBuffer(privateKey)) {
            throw new Error('Private key should be Buffer');
        }
        const buf = (0, account_1.privateToAddress)(privateKey);
        return new Address(buf);
    }
    /**
     * Generates an address for a newly created contract.
     * @param from The address which is creating this new address
     * @param nonce The nonce of the from account
     */
    static generate(from, nonce) {
        if (typeof nonce !== 'bigint') {
            throw new Error('Expected nonce to be a bigint');
        }
        return new Address((0, account_1.generateAddress)(from.buf, (0, bytes_1.bigIntToBuffer)(nonce)));
    }
    /**
     * Generates an address for a contract created using CREATE2.
     * @param from The address which is creating this new address
     * @param salt A salt
     * @param initCode The init code of the contract being created
     */
    static generate2(from, salt, initCode) {
        if (!Buffer.isBuffer(salt)) {
            throw new Error('Expected salt to be a Buffer');
        }
        if (!Buffer.isBuffer(initCode)) {
            throw new Error('Expected initCode to be a Buffer');
        }
        return new Address((0, account_1.generateAddress2)(from.buf, salt, initCode));
    }
    /**
     * Is address equal to another.
     */
    equals(address) {
        return this.buf.equals(address.buf);
    }
    /**
     * Is address zero.
     */
    isZero() {
        return this.equals(Address.zero());
    }
    /**
     * True if address is in the address range defined
     * by EIP-1352
     */
    isPrecompileOrSystemAddress() {
        const address = (0, bytes_1.bufferToBigInt)(this.buf);
        const rangeMin = BigInt(0);
        const rangeMax = BigInt('0xffff');
        return address >= rangeMin && address <= rangeMax;
    }
    /**
     * Returns hex encoding of address.
     */
    toString() {
        return '0x' + this.buf.toString('hex');
    }
    /**
     * Returns Buffer representation of address.
     */
    toBuffer() {
        return Buffer.from(this.buf);
    }
}
exports.Address = Address;

}).call(this)}).call(this,require("buffer").Buffer)
},{"./account":63,"./bytes":65,"buffer":89}],65:[function(require,module,exports){
(function (Buffer){(function (){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.bigIntToUnpaddedBuffer = exports.bigIntToHex = exports.bufArrToArr = exports.arrToBufArr = exports.validateNoLeadingZeroes = exports.baToJSON = exports.toUtf8 = exports.short = exports.addHexPrefix = exports.toUnsigned = exports.fromSigned = exports.bufferToInt = exports.bigIntToBuffer = exports.bufferToBigInt = exports.bufferToHex = exports.toBuffer = exports.unpadHexString = exports.unpadArray = exports.unpadBuffer = exports.setLengthRight = exports.setLengthLeft = exports.zeros = exports.intToBuffer = exports.intToHex = void 0;
const helpers_1 = require("./helpers");
const internal_1 = require("./internal");
/**
 * Converts a `Number` into a hex `String`
 * @param {Number} i
 * @return {String}
 */
const intToHex = function (i) {
    if (!Number.isSafeInteger(i) || i < 0) {
        throw new Error(`Received an invalid integer type: ${i}`);
    }
    return `0x${i.toString(16)}`;
};
exports.intToHex = intToHex;
/**
 * Converts an `Number` to a `Buffer`
 * @param {Number} i
 * @return {Buffer}
 */
const intToBuffer = function (i) {
    const hex = (0, exports.intToHex)(i);
    return Buffer.from((0, internal_1.padToEven)(hex.slice(2)), 'hex');
};
exports.intToBuffer = intToBuffer;
/**
 * Returns a buffer filled with 0s.
 * @param bytes the number of bytes the buffer should be
 */
const zeros = function (bytes) {
    return Buffer.allocUnsafe(bytes).fill(0);
};
exports.zeros = zeros;
/**
 * Pads a `Buffer` with zeros till it has `length` bytes.
 * Truncates the beginning or end of input if its length exceeds `length`.
 * @param msg the value to pad (Buffer)
 * @param length the number of bytes the output should be
 * @param right whether to start padding form the left or right
 * @return (Buffer)
 */
const setLength = function (msg, length, right) {
    const buf = (0, exports.zeros)(length);
    if (right) {
        if (msg.length < length) {
            msg.copy(buf);
            return buf;
        }
        return msg.slice(0, length);
    }
    else {
        if (msg.length < length) {
            msg.copy(buf, length - msg.length);
            return buf;
        }
        return msg.slice(-length);
    }
};
/**
 * Left Pads a `Buffer` with leading zeros till it has `length` bytes.
 * Or it truncates the beginning if it exceeds.
 * @param msg the value to pad (Buffer)
 * @param length the number of bytes the output should be
 * @return (Buffer)
 */
const setLengthLeft = function (msg, length) {
    (0, helpers_1.assertIsBuffer)(msg);
    return setLength(msg, length, false);
};
exports.setLengthLeft = setLengthLeft;
/**
 * Right Pads a `Buffer` with trailing zeros till it has `length` bytes.
 * it truncates the end if it exceeds.
 * @param msg the value to pad (Buffer)
 * @param length the number of bytes the output should be
 * @return (Buffer)
 */
const setLengthRight = function (msg, length) {
    (0, helpers_1.assertIsBuffer)(msg);
    return setLength(msg, length, true);
};
exports.setLengthRight = setLengthRight;
/**
 * Trims leading zeros from a `Buffer`, `String` or `Number[]`.
 * @param a (Buffer|Array|String)
 * @return (Buffer|Array|String)
 */
const stripZeros = function (a) {
    let first = a[0];
    while (a.length > 0 && first.toString() === '0') {
        a = a.slice(1);
        first = a[0];
    }
    return a;
};
/**
 * Trims leading zeros from a `Buffer`.
 * @param a (Buffer)
 * @return (Buffer)
 */
const unpadBuffer = function (a) {
    (0, helpers_1.assertIsBuffer)(a);
    return stripZeros(a);
};
exports.unpadBuffer = unpadBuffer;
/**
 * Trims leading zeros from an `Array` (of numbers).
 * @param a (number[])
 * @return (number[])
 */
const unpadArray = function (a) {
    (0, helpers_1.assertIsArray)(a);
    return stripZeros(a);
};
exports.unpadArray = unpadArray;
/**
 * Trims leading zeros from a hex-prefixed `String`.
 * @param a (String)
 * @return (String)
 */
const unpadHexString = function (a) {
    (0, helpers_1.assertIsHexString)(a);
    a = (0, internal_1.stripHexPrefix)(a);
    return ('0x' + stripZeros(a));
};
exports.unpadHexString = unpadHexString;
/**
 * Attempts to turn a value into a `Buffer`.
 * Inputs supported: `Buffer`, `String` (hex-prefixed), `Number`, null/undefined, `BigInt` and other objects
 * with a `toArray()` or `toBuffer()` method.
 * @param v the value
 */
const toBuffer = function (v) {
    if (v === null || v === undefined) {
        return Buffer.allocUnsafe(0);
    }
    if (Buffer.isBuffer(v)) {
        return Buffer.from(v);
    }
    if (Array.isArray(v) || v instanceof Uint8Array) {
        return Buffer.from(v);
    }
    if (typeof v === 'string') {
        if (!(0, internal_1.isHexString)(v)) {
            throw new Error(`Cannot convert string to buffer. toBuffer only supports 0x-prefixed hex strings and this string was given: ${v}`);
        }
        return Buffer.from((0, internal_1.padToEven)((0, internal_1.stripHexPrefix)(v)), 'hex');
    }
    if (typeof v === 'number') {
        return (0, exports.intToBuffer)(v);
    }
    if (typeof v === 'bigint') {
        if (v < BigInt(0)) {
            throw new Error(`Cannot convert negative bigint to buffer. Given: ${v}`);
        }
        let n = v.toString(16);
        if (n.length % 2)
            n = '0' + n;
        return Buffer.from(n, 'hex');
    }
    if (v.toArray) {
        // converts a BN to a Buffer
        return Buffer.from(v.toArray());
    }
    if (v.toBuffer) {
        return Buffer.from(v.toBuffer());
    }
    throw new Error('invalid type');
};
exports.toBuffer = toBuffer;
/**
 * Converts a `Buffer` into a `0x`-prefixed hex `String`.
 * @param buf `Buffer` object to convert
 */
const bufferToHex = function (buf) {
    buf = (0, exports.toBuffer)(buf);
    return '0x' + buf.toString('hex');
};
exports.bufferToHex = bufferToHex;
/**
 * Converts a {@link Buffer} to a {@link bigint}
 */
function bufferToBigInt(buf) {
    const hex = (0, exports.bufferToHex)(buf);
    if (hex === '0x') {
        return BigInt(0);
    }
    return BigInt(hex);
}
exports.bufferToBigInt = bufferToBigInt;
/**
 * Converts a {@link bigint} to a {@link Buffer}
 */
function bigIntToBuffer(num) {
    return (0, exports.toBuffer)('0x' + num.toString(16));
}
exports.bigIntToBuffer = bigIntToBuffer;
/**
 * Converts a `Buffer` to a `Number`.
 * @param buf `Buffer` object to convert
 * @throws If the input number exceeds 53 bits.
 */
const bufferToInt = function (buf) {
    const res = Number(bufferToBigInt(buf));
    if (!Number.isSafeInteger(res))
        throw new Error('Number exceeds 53 bits');
    return res;
};
exports.bufferToInt = bufferToInt;
/**
 * Interprets a `Buffer` as a signed integer and returns a `BigInt`. Assumes 256-bit numbers.
 * @param num Signed integer value
 */
const fromSigned = function (num) {
    return BigInt.asIntN(256, bufferToBigInt(num));
};
exports.fromSigned = fromSigned;
/**
 * Converts a `BigInt` to an unsigned integer and returns it as a `Buffer`. Assumes 256-bit numbers.
 * @param num
 */
const toUnsigned = function (num) {
    return bigIntToBuffer(BigInt.asUintN(256, num));
};
exports.toUnsigned = toUnsigned;
/**
 * Adds "0x" to a given `String` if it does not already start with "0x".
 */
const addHexPrefix = function (str) {
    if (typeof str !== 'string') {
        return str;
    }
    return (0, internal_1.isHexPrefixed)(str) ? str : '0x' + str;
};
exports.addHexPrefix = addHexPrefix;
/**
 * Shortens a string  or buffer's hex string representation to maxLength (default 50).
 *
 * Examples:
 *
 * Input:  '657468657265756d000000000000000000000000000000000000000000000000'
 * Output: '657468657265756d0000000000000000000000000000000000…'
 */
function short(buffer, maxLength = 50) {
    const bufferStr = Buffer.isBuffer(buffer) ? buffer.toString('hex') : buffer;
    if (bufferStr.length <= maxLength) {
        return bufferStr;
    }
    return bufferStr.slice(0, maxLength) + '…';
}
exports.short = short;
/**
 * Returns the utf8 string representation from a hex string.
 *
 * Examples:
 *
 * Input 1: '657468657265756d000000000000000000000000000000000000000000000000'
 * Input 2: '657468657265756d'
 * Input 3: '000000000000000000000000000000000000000000000000657468657265756d'
 *
 * Output (all 3 input variants): 'ethereum'
 *
 * Note that this method is not intended to be used with hex strings
 * representing quantities in both big endian or little endian notation.
 *
 * @param string Hex string, should be `0x` prefixed
 * @return Utf8 string
 */
const toUtf8 = function (hex) {
    const zerosRegexp = /^(00)+|(00)+$/g;
    hex = (0, internal_1.stripHexPrefix)(hex);
    if (hex.length % 2 !== 0) {
        throw new Error('Invalid non-even hex string input for toUtf8() provided');
    }
    const bufferVal = Buffer.from(hex.replace(zerosRegexp, ''), 'hex');
    return bufferVal.toString('utf8');
};
exports.toUtf8 = toUtf8;
/**
 * Converts a `Buffer` or `Array` to JSON.
 * @param ba (Buffer|Array)
 * @return (Array|String|null)
 */
const baToJSON = function (ba) {
    if (Buffer.isBuffer(ba)) {
        return `0x${ba.toString('hex')}`;
    }
    else if (ba instanceof Array) {
        const array = [];
        for (let i = 0; i < ba.length; i++) {
            array.push((0, exports.baToJSON)(ba[i]));
        }
        return array;
    }
};
exports.baToJSON = baToJSON;
/**
 * Checks provided Buffers for leading zeroes and throws if found.
 *
 * Examples:
 *
 * Valid values: 0x1, 0x, 0x01, 0x1234
 * Invalid values: 0x0, 0x00, 0x001, 0x0001
 *
 * Note: This method is useful for validating that RLP encoded integers comply with the rule that all
 * integer values encoded to RLP must be in the most compact form and contain no leading zero bytes
 * @param values An object containing string keys and Buffer values
 * @throws if any provided value is found to have leading zero bytes
 */
const validateNoLeadingZeroes = function (values) {
    for (const [k, v] of Object.entries(values)) {
        if (v !== undefined && v.length > 0 && v[0] === 0) {
            throw new Error(`${k} cannot have leading zeroes, received: ${v.toString('hex')}`);
        }
    }
};
exports.validateNoLeadingZeroes = validateNoLeadingZeroes;
function arrToBufArr(arr) {
    if (!Array.isArray(arr)) {
        return Buffer.from(arr);
    }
    return arr.map((a) => arrToBufArr(a));
}
exports.arrToBufArr = arrToBufArr;
function bufArrToArr(arr) {
    if (!Array.isArray(arr)) {
        return Uint8Array.from(arr ?? []);
    }
    return arr.map((a) => bufArrToArr(a));
}
exports.bufArrToArr = bufArrToArr;
/**
 * Converts a {@link bigint} to a `0x` prefixed hex string
 */
const bigIntToHex = (num) => {
    return '0x' + num.toString(16);
};
exports.bigIntToHex = bigIntToHex;
/**
 * Convert value from bigint to an unpadded Buffer
 * (useful for RLP transport)
 * @param value value to convert
 */
function bigIntToUnpaddedBuffer(value) {
    return (0, exports.unpadBuffer)(bigIntToBuffer(value));
}
exports.bigIntToUnpaddedBuffer = bigIntToUnpaddedBuffer;

}).call(this)}).call(this,require("buffer").Buffer)
},{"./helpers":67,"./internal":69,"buffer":89}],66:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.RLP_EMPTY_STRING = exports.KECCAK256_RLP = exports.KECCAK256_RLP_S = exports.KECCAK256_RLP_ARRAY = exports.KECCAK256_RLP_ARRAY_S = exports.KECCAK256_NULL = exports.KECCAK256_NULL_S = exports.TWO_POW256 = exports.SECP256K1_ORDER_DIV_2 = exports.SECP256K1_ORDER = exports.MAX_INTEGER_BIGINT = exports.MAX_INTEGER = exports.MAX_UINT64 = void 0;
const buffer_1 = require("buffer");
const secp256k1_1 = require("ethereum-cryptography/secp256k1");
/**
 * 2^64-1
 */
exports.MAX_UINT64 = BigInt('0xffffffffffffffff');
/**
 * The max integer that the evm can handle (2^256-1)
 */
exports.MAX_INTEGER = BigInt('0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff');
/**
 * The max integer that the evm can handle (2^256-1) as a bigint
 */
exports.MAX_INTEGER_BIGINT = BigInt(2) ** BigInt(256) - BigInt(1);
exports.SECP256K1_ORDER = secp256k1_1.CURVE.n;
exports.SECP256K1_ORDER_DIV_2 = secp256k1_1.CURVE.n / BigInt(2);
/**
 * 2^256
 */
exports.TWO_POW256 = BigInt('0x10000000000000000000000000000000000000000000000000000000000000000');
/**
 * Keccak-256 hash of null
 */
exports.KECCAK256_NULL_S = 'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470';
/**
 * Keccak-256 hash of null
 */
exports.KECCAK256_NULL = buffer_1.Buffer.from(exports.KECCAK256_NULL_S, 'hex');
/**
 * Keccak-256 of an RLP of an empty array
 */
exports.KECCAK256_RLP_ARRAY_S = '1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347';
/**
 * Keccak-256 of an RLP of an empty array
 */
exports.KECCAK256_RLP_ARRAY = buffer_1.Buffer.from(exports.KECCAK256_RLP_ARRAY_S, 'hex');
/**
 * Keccak-256 hash of the RLP of null
 */
exports.KECCAK256_RLP_S = '56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421';
/**
 * Keccak-256 hash of the RLP of null
 */
exports.KECCAK256_RLP = buffer_1.Buffer.from(exports.KECCAK256_RLP_S, 'hex');
/**
 *  RLP encoded empty string
 */
exports.RLP_EMPTY_STRING = buffer_1.Buffer.from([0x80]);

},{"buffer":89,"ethereum-cryptography/secp256k1":73}],67:[function(require,module,exports){
(function (Buffer){(function (){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.assertIsString = exports.assertIsArray = exports.assertIsBuffer = exports.assertIsHexString = void 0;
const internal_1 = require("./internal");
/**
 * Throws if a string is not hex prefixed
 * @param {string} input string to check hex prefix of
 */
const assertIsHexString = function (input) {
    if (!(0, internal_1.isHexString)(input)) {
        const msg = `This method only supports 0x-prefixed hex strings but input was: ${input}`;
        throw new Error(msg);
    }
};
exports.assertIsHexString = assertIsHexString;
/**
 * Throws if input is not a buffer
 * @param {Buffer} input value to check
 */
const assertIsBuffer = function (input) {
    if (!Buffer.isBuffer(input)) {
        const msg = `This method only supports Buffer but input was: ${input}`;
        throw new Error(msg);
    }
};
exports.assertIsBuffer = assertIsBuffer;
/**
 * Throws if input is not an array
 * @param {number[]} input value to check
 */
const assertIsArray = function (input) {
    if (!Array.isArray(input)) {
        const msg = `This method only supports number arrays but input was: ${input}`;
        throw new Error(msg);
    }
};
exports.assertIsArray = assertIsArray;
/**
 * Throws if input is not a string
 * @param {string} input value to check
 */
const assertIsString = function (input) {
    if (typeof input !== 'string') {
        const msg = `This method only supports strings but input was: ${input}`;
        throw new Error(msg);
    }
};
exports.assertIsString = assertIsString;

}).call(this)}).call(this,{"isBuffer":require("../../../is-buffer/index.js")})
},{"../../../is-buffer/index.js":85,"./internal":69}],68:[function(require,module,exports){
"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __exportStar = (this && this.__exportStar) || function(m, exports) {
    for (var p in m) if (p !== "default" && !Object.prototype.hasOwnProperty.call(exports, p)) __createBinding(exports, m, p);
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.toAscii = exports.stripHexPrefix = exports.padToEven = exports.isHexString = exports.isHexPrefixed = exports.getKeys = exports.getBinarySize = exports.fromUtf8 = exports.fromAscii = exports.arrayContainsArray = void 0;
/**
 * Constants
 */
__exportStar(require("./constants"), exports);
/**
 * Account class and helper functions
 */
__exportStar(require("./account"), exports);
/**
 * Address type
 */
__exportStar(require("./address"), exports);
/**
 * ECDSA signature
 */
__exportStar(require("./signature"), exports);
/**
 * Utilities for manipulating Buffers, byte arrays, etc.
 */
__exportStar(require("./bytes"), exports);
/**
 * Helpful TypeScript types
 */
__exportStar(require("./types"), exports);
/**
 * Export ethjs-util methods
 */
var internal_1 = require("./internal");
Object.defineProperty(exports, "arrayContainsArray", { enumerable: true, get: function () { return internal_1.arrayContainsArray; } });
Object.defineProperty(exports, "fromAscii", { enumerable: true, get: function () { return internal_1.fromAscii; } });
Object.defineProperty(exports, "fromUtf8", { enumerable: true, get: function () { return internal_1.fromUtf8; } });
Object.defineProperty(exports, "getBinarySize", { enumerable: true, get: function () { return internal_1.getBinarySize; } });
Object.defineProperty(exports, "getKeys", { enumerable: true, get: function () { return internal_1.getKeys; } });
Object.defineProperty(exports, "isHexPrefixed", { enumerable: true, get: function () { return internal_1.isHexPrefixed; } });
Object.defineProperty(exports, "isHexString", { enumerable: true, get: function () { return internal_1.isHexString; } });
Object.defineProperty(exports, "padToEven", { enumerable: true, get: function () { return internal_1.padToEven; } });
Object.defineProperty(exports, "stripHexPrefix", { enumerable: true, get: function () { return internal_1.stripHexPrefix; } });
Object.defineProperty(exports, "toAscii", { enumerable: true, get: function () { return internal_1.toAscii; } });

},{"./account":63,"./address":64,"./bytes":65,"./constants":66,"./internal":69,"./signature":70,"./types":71}],69:[function(require,module,exports){
(function (Buffer){(function (){
"use strict";
/*
The MIT License

Copyright (c) 2016 Nick Dodson. nickdodson.com

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.isHexString = exports.getKeys = exports.fromAscii = exports.fromUtf8 = exports.toAscii = exports.arrayContainsArray = exports.getBinarySize = exports.padToEven = exports.stripHexPrefix = exports.isHexPrefixed = void 0;
/**
 * Returns a `Boolean` on whether or not the a `String` starts with '0x'
 * @param str the string input value
 * @return a boolean if it is or is not hex prefixed
 * @throws if the str input is not a string
 */
function isHexPrefixed(str) {
    if (typeof str !== 'string') {
        throw new Error(`[isHexPrefixed] input must be type 'string', received type ${typeof str}`);
    }
    return str[0] === '0' && str[1] === 'x';
}
exports.isHexPrefixed = isHexPrefixed;
/**
 * Removes '0x' from a given `String` if present
 * @param str the string value
 * @returns the string without 0x prefix
 */
const stripHexPrefix = (str) => {
    if (typeof str !== 'string')
        throw new Error(`[stripHexPrefix] input must be type 'string', received ${typeof str}`);
    return isHexPrefixed(str) ? str.slice(2) : str;
};
exports.stripHexPrefix = stripHexPrefix;
/**
 * Pads a `String` to have an even length
 * @param value
 * @return output
 */
function padToEven(value) {
    let a = value;
    if (typeof a !== 'string') {
        throw new Error(`[padToEven] value must be type 'string', received ${typeof a}`);
    }
    if (a.length % 2)
        a = `0${a}`;
    return a;
}
exports.padToEven = padToEven;
/**
 * Get the binary size of a string
 * @param str
 * @returns the number of bytes contained within the string
 */
function getBinarySize(str) {
    if (typeof str !== 'string') {
        throw new Error(`[getBinarySize] method requires input type 'string', recieved ${typeof str}`);
    }
    return Buffer.byteLength(str, 'utf8');
}
exports.getBinarySize = getBinarySize;
/**
 * Returns TRUE if the first specified array contains all elements
 * from the second one. FALSE otherwise.
 *
 * @param superset
 * @param subset
 *
 */
function arrayContainsArray(superset, subset, some) {
    if (Array.isArray(superset) !== true) {
        throw new Error(`[arrayContainsArray] method requires input 'superset' to be an array, got type '${typeof superset}'`);
    }
    if (Array.isArray(subset) !== true) {
        throw new Error(`[arrayContainsArray] method requires input 'subset' to be an array, got type '${typeof subset}'`);
    }
    return subset[some === true ? 'some' : 'every']((value) => superset.indexOf(value) >= 0);
}
exports.arrayContainsArray = arrayContainsArray;
/**
 * Should be called to get ascii from its hex representation
 *
 * @param string in hex
 * @returns ascii string representation of hex value
 */
function toAscii(hex) {
    let str = '';
    let i = 0;
    const l = hex.length;
    if (hex.substring(0, 2) === '0x')
        i = 2;
    for (; i < l; i += 2) {
        const code = parseInt(hex.substr(i, 2), 16);
        str += String.fromCharCode(code);
    }
    return str;
}
exports.toAscii = toAscii;
/**
 * Should be called to get hex representation (prefixed by 0x) of utf8 string
 *
 * @param string
 * @param optional padding
 * @returns hex representation of input string
 */
function fromUtf8(stringValue) {
    const str = Buffer.from(stringValue, 'utf8');
    return `0x${padToEven(str.toString('hex')).replace(/^0+|0+$/g, '')}`;
}
exports.fromUtf8 = fromUtf8;
/**
 * Should be called to get hex representation (prefixed by 0x) of ascii string
 *
 * @param  string
 * @param  optional padding
 * @returns  hex representation of input string
 */
function fromAscii(stringValue) {
    let hex = '';
    for (let i = 0; i < stringValue.length; i++) {
        const code = stringValue.charCodeAt(i);
        const n = code.toString(16);
        hex += n.length < 2 ? `0${n}` : n;
    }
    return `0x${hex}`;
}
exports.fromAscii = fromAscii;
/**
 * Returns the keys from an array of objects.
 * @example
 * ```js
 * getKeys([{a: '1', b: '2'}, {a: '3', b: '4'}], 'a') => ['1', '3']
 *````
 * @param  params
 * @param  key
 * @param  allowEmpty
 * @returns output just a simple array of output keys
 */
function getKeys(params, key, allowEmpty) {
    if (!Array.isArray(params)) {
        throw new Error(`[getKeys] method expects input 'params' to be an array, got ${typeof params}`);
    }
    if (typeof key !== 'string') {
        throw new Error(`[getKeys] method expects input 'key' to be type 'string', got ${typeof params}`);
    }
    const result = [];
    for (let i = 0; i < params.length; i++) {
        let value = params[i][key];
        if (allowEmpty === true && !value) {
            value = '';
        }
        else if (typeof value !== 'string') {
            throw new Error(`invalid abi - expected type 'string', received ${typeof value}`);
        }
        result.push(value);
    }
    return result;
}
exports.getKeys = getKeys;
/**
 * Is the string a hex string.
 *
 * @param  value
 * @param  length
 * @returns  output the string is a hex string
 */
function isHexString(value, length) {
    if (typeof value !== 'string' || !value.match(/^0x[0-9A-Fa-f]*$/))
        return false;
    if (typeof length !== 'undefined' && length > 0 && value.length !== 2 + 2 * length)
        return false;
    return true;
}
exports.isHexString = isHexString;

}).call(this)}).call(this,require("buffer").Buffer)
},{"buffer":89}],70:[function(require,module,exports){
(function (Buffer){(function (){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.hashPersonalMessage = exports.isValidSignature = exports.fromRpcSig = exports.toCompactSig = exports.toRpcSig = exports.ecrecover = exports.ecsign = void 0;
const keccak_1 = require("ethereum-cryptography/keccak");
const secp256k1_1 = require("ethereum-cryptography/secp256k1");
const bytes_1 = require("./bytes");
const constants_1 = require("./constants");
const helpers_1 = require("./helpers");
/**
 * Returns the ECDSA signature of a message hash.
 *
 * If `chainId` is provided assume an EIP-155-style signature and calculate the `v` value
 * accordingly, otherwise return a "static" `v` just derived from the `recovery` bit
 */
function ecsign(msgHash, privateKey, chainId) {
    const [signature, recovery] = (0, secp256k1_1.signSync)(msgHash, privateKey, { recovered: true, der: false });
    const r = Buffer.from(signature.slice(0, 32));
    const s = Buffer.from(signature.slice(32, 64));
    const v = chainId === undefined
        ? BigInt(recovery + 27)
        : BigInt(recovery + 35) + BigInt(chainId) * BigInt(2);
    return { r, s, v };
}
exports.ecsign = ecsign;
function calculateSigRecovery(v, chainId) {
    if (v === BigInt(0) || v === BigInt(1))
        return v;
    if (chainId === undefined) {
        return v - BigInt(27);
    }
    return v - (chainId * BigInt(2) + BigInt(35));
}
function isValidSigRecovery(recovery) {
    return recovery === BigInt(0) || recovery === BigInt(1);
}
/**
 * ECDSA public key recovery from signature.
 * NOTE: Accepts `v === 0 | v === 1` for EIP1559 transactions
 * @returns Recovered public key
 */
const ecrecover = function (msgHash, v, r, s, chainId) {
    const signature = Buffer.concat([(0, bytes_1.setLengthLeft)(r, 32), (0, bytes_1.setLengthLeft)(s, 32)], 64);
    const recovery = calculateSigRecovery(v, chainId);
    if (!isValidSigRecovery(recovery)) {
        throw new Error('Invalid signature v value');
    }
    const senderPubKey = (0, secp256k1_1.recoverPublicKey)(msgHash, signature, Number(recovery));
    return Buffer.from(senderPubKey.slice(1));
};
exports.ecrecover = ecrecover;
/**
 * Convert signature parameters into the format of `eth_sign` RPC method.
 * NOTE: Accepts `v === 0 | v === 1` for EIP1559 transactions
 * @returns Signature
 */
const toRpcSig = function (v, r, s, chainId) {
    const recovery = calculateSigRecovery(v, chainId);
    if (!isValidSigRecovery(recovery)) {
        throw new Error('Invalid signature v value');
    }
    // geth (and the RPC eth_sign method) uses the 65 byte format used by Bitcoin
    return (0, bytes_1.bufferToHex)(Buffer.concat([(0, bytes_1.setLengthLeft)(r, 32), (0, bytes_1.setLengthLeft)(s, 32), (0, bytes_1.toBuffer)(v)]));
};
exports.toRpcSig = toRpcSig;
/**
 * Convert signature parameters into the format of Compact Signature Representation (EIP-2098).
 * NOTE: Accepts `v === 0 | v === 1` for EIP1559 transactions
 * @returns Signature
 */
const toCompactSig = function (v, r, s, chainId) {
    const recovery = calculateSigRecovery(v, chainId);
    if (!isValidSigRecovery(recovery)) {
        throw new Error('Invalid signature v value');
    }
    let ss = s;
    if ((v > BigInt(28) && v % BigInt(2) === BigInt(1)) || v === BigInt(1) || v === BigInt(28)) {
        ss = Buffer.from(s);
        ss[0] |= 0x80;
    }
    return (0, bytes_1.bufferToHex)(Buffer.concat([(0, bytes_1.setLengthLeft)(r, 32), (0, bytes_1.setLengthLeft)(ss, 32)]));
};
exports.toCompactSig = toCompactSig;
/**
 * Convert signature format of the `eth_sign` RPC method to signature parameters
 *
 * NOTE: For an extracted `v` value < 27 (see Geth bug https://github.com/ethereum/go-ethereum/issues/2053)
 * `v + 27` is returned for the `v` value
 * NOTE: After EIP1559, `v` could be `0` or `1` but this function assumes
 * it's a signed message (EIP-191 or EIP-712) adding `27` at the end. Remove if needed.
 */
const fromRpcSig = function (sig) {
    const buf = (0, bytes_1.toBuffer)(sig);
    let r;
    let s;
    let v;
    if (buf.length >= 65) {
        r = buf.slice(0, 32);
        s = buf.slice(32, 64);
        v = (0, bytes_1.bufferToBigInt)(buf.slice(64));
    }
    else if (buf.length === 64) {
        // Compact Signature Representation (https://eips.ethereum.org/EIPS/eip-2098)
        r = buf.slice(0, 32);
        s = buf.slice(32, 64);
        v = BigInt((0, bytes_1.bufferToInt)(buf.slice(32, 33)) >> 7);
        s[0] &= 0x7f;
    }
    else {
        throw new Error('Invalid signature length');
    }
    // support both versions of `eth_sign` responses
    if (v < 27) {
        v = v + BigInt(27);
    }
    return {
        v,
        r,
        s,
    };
};
exports.fromRpcSig = fromRpcSig;
/**
 * Validate a ECDSA signature.
 * NOTE: Accepts `v === 0 | v === 1` for EIP1559 transactions
 * @param homesteadOrLater Indicates whether this is being used on either the homestead hardfork or a later one
 */
const isValidSignature = function (v, r, s, homesteadOrLater = true, chainId) {
    if (r.length !== 32 || s.length !== 32) {
        return false;
    }
    if (!isValidSigRecovery(calculateSigRecovery(v, chainId))) {
        return false;
    }
    const rBigInt = (0, bytes_1.bufferToBigInt)(r);
    const sBigInt = (0, bytes_1.bufferToBigInt)(s);
    if (rBigInt === BigInt(0) ||
        rBigInt >= constants_1.SECP256K1_ORDER ||
        sBigInt === BigInt(0) ||
        sBigInt >= constants_1.SECP256K1_ORDER) {
        return false;
    }
    if (homesteadOrLater && sBigInt >= constants_1.SECP256K1_ORDER_DIV_2) {
        return false;
    }
    return true;
};
exports.isValidSignature = isValidSignature;
/**
 * Returns the keccak-256 hash of `message`, prefixed with the header used by the `eth_sign` RPC call.
 * The output of this function can be fed into `ecsign` to produce the same signature as the `eth_sign`
 * call for a given `message`, or fed to `ecrecover` along with a signature to recover the public key
 * used to produce the signature.
 */
const hashPersonalMessage = function (message) {
    (0, helpers_1.assertIsBuffer)(message);
    const prefix = Buffer.from(`\u0019Ethereum Signed Message:\n${message.length}`, 'utf-8');
    return Buffer.from((0, keccak_1.keccak256)(Buffer.concat([prefix, message])));
};
exports.hashPersonalMessage = hashPersonalMessage;

}).call(this)}).call(this,require("buffer").Buffer)
},{"./bytes":65,"./constants":66,"./helpers":67,"buffer":89,"ethereum-cryptography/keccak":72,"ethereum-cryptography/secp256k1":73}],71:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.toType = exports.TypeOutput = void 0;
const bytes_1 = require("./bytes");
const internal_1 = require("./internal");
/**
 * Type output options
 */
var TypeOutput;
(function (TypeOutput) {
    TypeOutput[TypeOutput["Number"] = 0] = "Number";
    TypeOutput[TypeOutput["BigInt"] = 1] = "BigInt";
    TypeOutput[TypeOutput["Buffer"] = 2] = "Buffer";
    TypeOutput[TypeOutput["PrefixedHexString"] = 3] = "PrefixedHexString";
})(TypeOutput = exports.TypeOutput || (exports.TypeOutput = {}));
function toType(input, outputType) {
    if (input === null) {
        return null;
    }
    if (input === undefined) {
        return undefined;
    }
    if (typeof input === 'string' && !(0, internal_1.isHexString)(input)) {
        throw new Error(`A string must be provided with a 0x-prefix, given: ${input}`);
    }
    else if (typeof input === 'number' && !Number.isSafeInteger(input)) {
        throw new Error('The provided number is greater than MAX_SAFE_INTEGER (please use an alternative input type)');
    }
    const output = (0, bytes_1.toBuffer)(input);
    switch (outputType) {
        case TypeOutput.Buffer:
            return output;
        case TypeOutput.BigInt:
            return (0, bytes_1.bufferToBigInt)(output);
        case TypeOutput.Number: {
            const bigInt = (0, bytes_1.bufferToBigInt)(output);
            if (bigInt > BigInt(Number.MAX_SAFE_INTEGER)) {
                throw new Error('The provided number is greater than MAX_SAFE_INTEGER (please use an alternative output type)');
            }
            return Number(bigInt);
        }
        case TypeOutput.PrefixedHexString:
            return (0, bytes_1.bufferToHex)(output);
        default:
            throw new Error('unknown outputType');
    }
}
exports.toType = toType;

},{"./bytes":65,"./internal":69}],72:[function(require,module,exports){
arguments[4][61][0].apply(exports,arguments)
},{"./utils":74,"@noble/hashes/sha3":81,"dup":61}],73:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.schnorr = exports.Signature = exports.Point = exports.CURVE = exports.utils = exports.getSharedSecret = exports.recoverPublicKey = exports.verify = exports.signSync = exports.sign = exports.getPublicKey = void 0;
const hmac_1 = require("@noble/hashes/hmac");
const sha256_1 = require("@noble/hashes/sha256");
const secp256k1_1 = require("@noble/secp256k1");
var secp256k1_2 = require("@noble/secp256k1");
Object.defineProperty(exports, "getPublicKey", { enumerable: true, get: function () { return secp256k1_2.getPublicKey; } });
Object.defineProperty(exports, "sign", { enumerable: true, get: function () { return secp256k1_2.sign; } });
Object.defineProperty(exports, "signSync", { enumerable: true, get: function () { return secp256k1_2.signSync; } });
Object.defineProperty(exports, "verify", { enumerable: true, get: function () { return secp256k1_2.verify; } });
Object.defineProperty(exports, "recoverPublicKey", { enumerable: true, get: function () { return secp256k1_2.recoverPublicKey; } });
Object.defineProperty(exports, "getSharedSecret", { enumerable: true, get: function () { return secp256k1_2.getSharedSecret; } });
Object.defineProperty(exports, "utils", { enumerable: true, get: function () { return secp256k1_2.utils; } });
Object.defineProperty(exports, "CURVE", { enumerable: true, get: function () { return secp256k1_2.CURVE; } });
Object.defineProperty(exports, "Point", { enumerable: true, get: function () { return secp256k1_2.Point; } });
Object.defineProperty(exports, "Signature", { enumerable: true, get: function () { return secp256k1_2.Signature; } });
Object.defineProperty(exports, "schnorr", { enumerable: true, get: function () { return secp256k1_2.schnorr; } });
// Enable sync API for noble-secp256k1
secp256k1_1.utils.hmacSha256Sync = (key, ...messages) => {
    const h = hmac_1.hmac.create(sha256_1.sha256, key);
    messages.forEach(msg => h.update(msg));
    return h.digest();
};

},{"@noble/hashes/hmac":79,"@noble/hashes/sha256":80,"@noble/secp256k1":83}],74:[function(require,module,exports){
arguments[4][62][0].apply(exports,arguments)
},{"@noble/hashes/_assert":75,"@noble/hashes/utils":82,"dup":62}],75:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.output = exports.exists = exports.hash = exports.bytes = exports.bool = exports.number = void 0;
function number(n) {
    if (!Number.isSafeInteger(n) || n < 0)
        throw new Error(`Wrong positive integer: ${n}`);
}
exports.number = number;
function bool(b) {
    if (typeof b !== 'boolean')
        throw new Error(`Expected boolean, not ${b}`);
}
exports.bool = bool;
function bytes(b, ...lengths) {
    if (!(b instanceof Uint8Array))
        throw new TypeError('Expected Uint8Array');
    if (lengths.length > 0 && !lengths.includes(b.length))
        throw new TypeError(`Expected Uint8Array of length ${lengths}, not of length=${b.length}`);
}
exports.bytes = bytes;
function hash(hash) {
    if (typeof hash !== 'function' || typeof hash.create !== 'function')
        throw new Error('Hash should be wrapped by utils.wrapConstructor');
    number(hash.outputLen);
    number(hash.blockLen);
}
exports.hash = hash;
function exists(instance, checkFinished = true) {
    if (instance.destroyed)
        throw new Error('Hash instance has been destroyed');
    if (checkFinished && instance.finished)
        throw new Error('Hash#digest() has already been called');
}
exports.exists = exists;
function output(out, instance) {
    bytes(out);
    const min = instance.outputLen;
    if (out.length < min) {
        throw new Error(`digestInto() expects output buffer of length at least ${min}`);
    }
}
exports.output = output;
const assert = {
    number,
    bool,
    bytes,
    hash,
    exists,
    output,
};
exports.default = assert;

},{}],76:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.SHA2 = void 0;
const _assert_js_1 = require("./_assert.js");
const utils_js_1 = require("./utils.js");
// Polyfill for Safari 14
function setBigUint64(view, byteOffset, value, isLE) {
    if (typeof view.setBigUint64 === 'function')
        return view.setBigUint64(byteOffset, value, isLE);
    const _32n = BigInt(32);
    const _u32_max = BigInt(0xffffffff);
    const wh = Number((value >> _32n) & _u32_max);
    const wl = Number(value & _u32_max);
    const h = isLE ? 4 : 0;
    const l = isLE ? 0 : 4;
    view.setUint32(byteOffset + h, wh, isLE);
    view.setUint32(byteOffset + l, wl, isLE);
}
// Base SHA2 class (RFC 6234)
class SHA2 extends utils_js_1.Hash {
    constructor(blockLen, outputLen, padOffset, isLE) {
        super();
        this.blockLen = blockLen;
        this.outputLen = outputLen;
        this.padOffset = padOffset;
        this.isLE = isLE;
        this.finished = false;
        this.length = 0;
        this.pos = 0;
        this.destroyed = false;
        this.buffer = new Uint8Array(blockLen);
        this.view = (0, utils_js_1.createView)(this.buffer);
    }
    update(data) {
        _assert_js_1.default.exists(this);
        const { view, buffer, blockLen } = this;
        data = (0, utils_js_1.toBytes)(data);
        const len = data.length;
        for (let pos = 0; pos < len;) {
            const take = Math.min(blockLen - this.pos, len - pos);
            // Fast path: we have at least one block in input, cast it to view and process
            if (take === blockLen) {
                const dataView = (0, utils_js_1.createView)(data);
                for (; blockLen <= len - pos; pos += blockLen)
                    this.process(dataView, pos);
                continue;
            }
            buffer.set(data.subarray(pos, pos + take), this.pos);
            this.pos += take;
            pos += take;
            if (this.pos === blockLen) {
                this.process(view, 0);
                this.pos = 0;
            }
        }
        this.length += data.length;
        this.roundClean();
        return this;
    }
    digestInto(out) {
        _assert_js_1.default.exists(this);
        _assert_js_1.default.output(out, this);
        this.finished = true;
        // Padding
        // We can avoid allocation of buffer for padding completely if it
        // was previously not allocated here. But it won't change performance.
        const { buffer, view, blockLen, isLE } = this;
        let { pos } = this;
        // append the bit '1' to the message
        buffer[pos++] = 0b10000000;
        this.buffer.subarray(pos).fill(0);
        // we have less than padOffset left in buffer, so we cannot put length in current block, need process it and pad again
        if (this.padOffset > blockLen - pos) {
            this.process(view, 0);
            pos = 0;
        }
        // Pad until full block byte with zeros
        for (let i = pos; i < blockLen; i++)
            buffer[i] = 0;
        // Note: sha512 requires length to be 128bit integer, but length in JS will overflow before that
        // You need to write around 2 exabytes (u64_max / 8 / (1024**6)) for this to happen.
        // So we just write lowest 64 bits of that value.
        setBigUint64(view, blockLen - 8, BigInt(this.length * 8), isLE);
        this.process(view, 0);
        const oview = (0, utils_js_1.createView)(out);
        this.get().forEach((v, i) => oview.setUint32(4 * i, v, isLE));
    }
    digest() {
        const { buffer, outputLen } = this;
        this.digestInto(buffer);
        const res = buffer.slice(0, outputLen);
        this.destroy();
        return res;
    }
    _cloneInto(to) {
        to || (to = new this.constructor());
        to.set(...this.get());
        const { blockLen, buffer, length, finished, destroyed, pos } = this;
        to.length = length;
        to.pos = pos;
        to.finished = finished;
        to.destroyed = destroyed;
        if (length % blockLen)
            to.buffer.set(buffer);
        return to;
    }
}
exports.SHA2 = SHA2;

},{"./_assert.js":75,"./utils.js":82}],77:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.add = exports.toBig = exports.split = exports.fromBig = void 0;
const U32_MASK64 = BigInt(2 ** 32 - 1);
const _32n = BigInt(32);
// We are not using BigUint64Array, because they are extremely slow as per 2022
function fromBig(n, le = false) {
    if (le)
        return { h: Number(n & U32_MASK64), l: Number((n >> _32n) & U32_MASK64) };
    return { h: Number((n >> _32n) & U32_MASK64) | 0, l: Number(n & U32_MASK64) | 0 };
}
exports.fromBig = fromBig;
function split(lst, le = false) {
    let Ah = new Uint32Array(lst.length);
    let Al = new Uint32Array(lst.length);
    for (let i = 0; i < lst.length; i++) {
        const { h, l } = fromBig(lst[i], le);
        [Ah[i], Al[i]] = [h, l];
    }
    return [Ah, Al];
}
exports.split = split;
const toBig = (h, l) => (BigInt(h >>> 0) << _32n) | BigInt(l >>> 0);
exports.toBig = toBig;
// for Shift in [0, 32)
const shrSH = (h, l, s) => h >>> s;
const shrSL = (h, l, s) => (h << (32 - s)) | (l >>> s);
// Right rotate for Shift in [1, 32)
const rotrSH = (h, l, s) => (h >>> s) | (l << (32 - s));
const rotrSL = (h, l, s) => (h << (32 - s)) | (l >>> s);
// Right rotate for Shift in (32, 64), NOTE: 32 is special case.
const rotrBH = (h, l, s) => (h << (64 - s)) | (l >>> (s - 32));
const rotrBL = (h, l, s) => (h >>> (s - 32)) | (l << (64 - s));
// Right rotate for shift===32 (just swaps l&h)
const rotr32H = (h, l) => l;
const rotr32L = (h, l) => h;
// Left rotate for Shift in [1, 32)
const rotlSH = (h, l, s) => (h << s) | (l >>> (32 - s));
const rotlSL = (h, l, s) => (l << s) | (h >>> (32 - s));
// Left rotate for Shift in (32, 64), NOTE: 32 is special case.
const rotlBH = (h, l, s) => (l << (s - 32)) | (h >>> (64 - s));
const rotlBL = (h, l, s) => (h << (s - 32)) | (l >>> (64 - s));
// JS uses 32-bit signed integers for bitwise operations which means we cannot
// simple take carry out of low bit sum by shift, we need to use division.
// Removing "export" has 5% perf penalty -_-
function add(Ah, Al, Bh, Bl) {
    const l = (Al >>> 0) + (Bl >>> 0);
    return { h: (Ah + Bh + ((l / 2 ** 32) | 0)) | 0, l: l | 0 };
}
exports.add = add;
// Addition with more than 2 elements
const add3L = (Al, Bl, Cl) => (Al >>> 0) + (Bl >>> 0) + (Cl >>> 0);
const add3H = (low, Ah, Bh, Ch) => (Ah + Bh + Ch + ((low / 2 ** 32) | 0)) | 0;
const add4L = (Al, Bl, Cl, Dl) => (Al >>> 0) + (Bl >>> 0) + (Cl >>> 0) + (Dl >>> 0);
const add4H = (low, Ah, Bh, Ch, Dh) => (Ah + Bh + Ch + Dh + ((low / 2 ** 32) | 0)) | 0;
const add5L = (Al, Bl, Cl, Dl, El) => (Al >>> 0) + (Bl >>> 0) + (Cl >>> 0) + (Dl >>> 0) + (El >>> 0);
const add5H = (low, Ah, Bh, Ch, Dh, Eh) => (Ah + Bh + Ch + Dh + Eh + ((low / 2 ** 32) | 0)) | 0;
// prettier-ignore
const u64 = {
    fromBig, split, toBig: exports.toBig,
    shrSH, shrSL,
    rotrSH, rotrSL, rotrBH, rotrBL,
    rotr32H, rotr32L,
    rotlSH, rotlSL, rotlBH, rotlBL,
    add, add3L, add3H, add4L, add4H, add5H, add5L,
};
exports.default = u64;

},{}],78:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.crypto = void 0;
exports.crypto = {
    node: undefined,
    web: typeof self === 'object' && 'crypto' in self ? self.crypto : undefined,
};

},{}],79:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.hmac = void 0;
const _assert_js_1 = require("./_assert.js");
const utils_js_1 = require("./utils.js");
// HMAC (RFC 2104)
class HMAC extends utils_js_1.Hash {
    constructor(hash, _key) {
        super();
        this.finished = false;
        this.destroyed = false;
        _assert_js_1.default.hash(hash);
        const key = (0, utils_js_1.toBytes)(_key);
        this.iHash = hash.create();
        if (!(this.iHash instanceof utils_js_1.Hash))
            throw new TypeError('Expected instance of class which extends utils.Hash');
        const blockLen = (this.blockLen = this.iHash.blockLen);
        this.outputLen = this.iHash.outputLen;
        const pad = new Uint8Array(blockLen);
        // blockLen can be bigger than outputLen
        pad.set(key.length > this.iHash.blockLen ? hash.create().update(key).digest() : key);
        for (let i = 0; i < pad.length; i++)
            pad[i] ^= 0x36;
        this.iHash.update(pad);
        // By doing update (processing of first block) of outer hash here we can re-use it between multiple calls via clone
        this.oHash = hash.create();
        // Undo internal XOR && apply outer XOR
        for (let i = 0; i < pad.length; i++)
            pad[i] ^= 0x36 ^ 0x5c;
        this.oHash.update(pad);
        pad.fill(0);
    }
    update(buf) {
        _assert_js_1.default.exists(this);
        this.iHash.update(buf);
        return this;
    }
    digestInto(out) {
        _assert_js_1.default.exists(this);
        _assert_js_1.default.bytes(out, this.outputLen);
        this.finished = true;
        this.iHash.digestInto(out);
        this.oHash.update(out);
        this.oHash.digestInto(out);
        this.destroy();
    }
    digest() {
        const out = new Uint8Array(this.oHash.outputLen);
        this.digestInto(out);
        return out;
    }
    _cloneInto(to) {
        // Create new instance without calling constructor since key already in state and we don't know it.
        to || (to = Object.create(Object.getPrototypeOf(this), {}));
        const { oHash, iHash, finished, destroyed, blockLen, outputLen } = this;
        to = to;
        to.finished = finished;
        to.destroyed = destroyed;
        to.blockLen = blockLen;
        to.outputLen = outputLen;
        to.oHash = oHash._cloneInto(to.oHash);
        to.iHash = iHash._cloneInto(to.iHash);
        return to;
    }
    destroy() {
        this.destroyed = true;
        this.oHash.destroy();
        this.iHash.destroy();
    }
}
/**
 * HMAC: RFC2104 message authentication code.
 * @param hash - function that would be used e.g. sha256
 * @param key - message key
 * @param message - message data
 */
const hmac = (hash, key, message) => new HMAC(hash, key).update(message).digest();
exports.hmac = hmac;
exports.hmac.create = (hash, key) => new HMAC(hash, key);

},{"./_assert.js":75,"./utils.js":82}],80:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.sha256 = void 0;
const _sha2_js_1 = require("./_sha2.js");
const utils_js_1 = require("./utils.js");
// Choice: a ? b : c
const Chi = (a, b, c) => (a & b) ^ (~a & c);
// Majority function, true if any two inpust is true
const Maj = (a, b, c) => (a & b) ^ (a & c) ^ (b & c);
// Round constants:
// first 32 bits of the fractional parts of the cube roots of the first 64 primes 2..311)
// prettier-ignore
const SHA256_K = new Uint32Array([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]);
// Initial state (first 32 bits of the fractional parts of the square roots of the first 8 primes 2..19):
// prettier-ignore
const IV = new Uint32Array([
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
]);
// Temporary buffer, not used to store anything between runs
// Named this way because it matches specification.
const SHA256_W = new Uint32Array(64);
class SHA256 extends _sha2_js_1.SHA2 {
    constructor() {
        super(64, 32, 8, false);
        // We cannot use array here since array allows indexing by variable
        // which means optimizer/compiler cannot use registers.
        this.A = IV[0] | 0;
        this.B = IV[1] | 0;
        this.C = IV[2] | 0;
        this.D = IV[3] | 0;
        this.E = IV[4] | 0;
        this.F = IV[5] | 0;
        this.G = IV[6] | 0;
        this.H = IV[7] | 0;
    }
    get() {
        const { A, B, C, D, E, F, G, H } = this;
        return [A, B, C, D, E, F, G, H];
    }
    // prettier-ignore
    set(A, B, C, D, E, F, G, H) {
        this.A = A | 0;
        this.B = B | 0;
        this.C = C | 0;
        this.D = D | 0;
        this.E = E | 0;
        this.F = F | 0;
        this.G = G | 0;
        this.H = H | 0;
    }
    process(view, offset) {
        // Extend the first 16 words into the remaining 48 words w[16..63] of the message schedule array
        for (let i = 0; i < 16; i++, offset += 4)
            SHA256_W[i] = view.getUint32(offset, false);
        for (let i = 16; i < 64; i++) {
            const W15 = SHA256_W[i - 15];
            const W2 = SHA256_W[i - 2];
            const s0 = (0, utils_js_1.rotr)(W15, 7) ^ (0, utils_js_1.rotr)(W15, 18) ^ (W15 >>> 3);
            const s1 = (0, utils_js_1.rotr)(W2, 17) ^ (0, utils_js_1.rotr)(W2, 19) ^ (W2 >>> 10);
            SHA256_W[i] = (s1 + SHA256_W[i - 7] + s0 + SHA256_W[i - 16]) | 0;
        }
        // Compression function main loop, 64 rounds
        let { A, B, C, D, E, F, G, H } = this;
        for (let i = 0; i < 64; i++) {
            const sigma1 = (0, utils_js_1.rotr)(E, 6) ^ (0, utils_js_1.rotr)(E, 11) ^ (0, utils_js_1.rotr)(E, 25);
            const T1 = (H + sigma1 + Chi(E, F, G) + SHA256_K[i] + SHA256_W[i]) | 0;
            const sigma0 = (0, utils_js_1.rotr)(A, 2) ^ (0, utils_js_1.rotr)(A, 13) ^ (0, utils_js_1.rotr)(A, 22);
            const T2 = (sigma0 + Maj(A, B, C)) | 0;
            H = G;
            G = F;
            F = E;
            E = (D + T1) | 0;
            D = C;
            C = B;
            B = A;
            A = (T1 + T2) | 0;
        }
        // Add the compressed chunk to the current hash value
        A = (A + this.A) | 0;
        B = (B + this.B) | 0;
        C = (C + this.C) | 0;
        D = (D + this.D) | 0;
        E = (E + this.E) | 0;
        F = (F + this.F) | 0;
        G = (G + this.G) | 0;
        H = (H + this.H) | 0;
        this.set(A, B, C, D, E, F, G, H);
    }
    roundClean() {
        SHA256_W.fill(0);
    }
    destroy() {
        this.set(0, 0, 0, 0, 0, 0, 0, 0);
        this.buffer.fill(0);
    }
}
/**
 * SHA2-256 hash function
 * @param message - data that would be hashed
 */
exports.sha256 = (0, utils_js_1.wrapConstructor)(() => new SHA256());

},{"./_sha2.js":76,"./utils.js":82}],81:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.shake256 = exports.shake128 = exports.keccak_512 = exports.keccak_384 = exports.keccak_256 = exports.keccak_224 = exports.sha3_512 = exports.sha3_384 = exports.sha3_256 = exports.sha3_224 = exports.Keccak = exports.keccakP = void 0;
const _assert_js_1 = require("./_assert.js");
const _u64_js_1 = require("./_u64.js");
const utils_js_1 = require("./utils.js");
// Various per round constants calculations
const [SHA3_PI, SHA3_ROTL, _SHA3_IOTA] = [[], [], []];
const _0n = BigInt(0);
const _1n = BigInt(1);
const _2n = BigInt(2);
const _7n = BigInt(7);
const _256n = BigInt(256);
const _0x71n = BigInt(0x71);
for (let round = 0, R = _1n, x = 1, y = 0; round < 24; round++) {
    // Pi
    [x, y] = [y, (2 * x + 3 * y) % 5];
    SHA3_PI.push(2 * (5 * y + x));
    // Rotational
    SHA3_ROTL.push((((round + 1) * (round + 2)) / 2) % 64);
    // Iota
    let t = _0n;
    for (let j = 0; j < 7; j++) {
        R = ((R << _1n) ^ ((R >> _7n) * _0x71n)) % _256n;
        if (R & _2n)
            t ^= _1n << ((_1n << BigInt(j)) - _1n);
    }
    _SHA3_IOTA.push(t);
}
const [SHA3_IOTA_H, SHA3_IOTA_L] = _u64_js_1.default.split(_SHA3_IOTA, true);
// Left rotation (without 0, 32, 64)
const rotlH = (h, l, s) => s > 32 ? _u64_js_1.default.rotlBH(h, l, s) : _u64_js_1.default.rotlSH(h, l, s);
const rotlL = (h, l, s) => s > 32 ? _u64_js_1.default.rotlBL(h, l, s) : _u64_js_1.default.rotlSL(h, l, s);
// Same as keccakf1600, but allows to skip some rounds
function keccakP(s, rounds = 24) {
    const B = new Uint32Array(5 * 2);
    // NOTE: all indices are x2 since we store state as u32 instead of u64 (bigints to slow in js)
    for (let round = 24 - rounds; round < 24; round++) {
        // Theta θ
        for (let x = 0; x < 10; x++)
            B[x] = s[x] ^ s[x + 10] ^ s[x + 20] ^ s[x + 30] ^ s[x + 40];
        for (let x = 0; x < 10; x += 2) {
            const idx1 = (x + 8) % 10;
            const idx0 = (x + 2) % 10;
            const B0 = B[idx0];
            const B1 = B[idx0 + 1];
            const Th = rotlH(B0, B1, 1) ^ B[idx1];
            const Tl = rotlL(B0, B1, 1) ^ B[idx1 + 1];
            for (let y = 0; y < 50; y += 10) {
                s[x + y] ^= Th;
                s[x + y + 1] ^= Tl;
            }
        }
        // Rho (ρ) and Pi (π)
        let curH = s[2];
        let curL = s[3];
        for (let t = 0; t < 24; t++) {
            const shift = SHA3_ROTL[t];
            const Th = rotlH(curH, curL, shift);
            const Tl = rotlL(curH, curL, shift);
            const PI = SHA3_PI[t];
            curH = s[PI];
            curL = s[PI + 1];
            s[PI] = Th;
            s[PI + 1] = Tl;
        }
        // Chi (χ)
        for (let y = 0; y < 50; y += 10) {
            for (let x = 0; x < 10; x++)
                B[x] = s[y + x];
            for (let x = 0; x < 10; x++)
                s[y + x] ^= ~B[(x + 2) % 10] & B[(x + 4) % 10];
        }
        // Iota (ι)
        s[0] ^= SHA3_IOTA_H[round];
        s[1] ^= SHA3_IOTA_L[round];
    }
    B.fill(0);
}
exports.keccakP = keccakP;
class Keccak extends utils_js_1.Hash {
    // NOTE: we accept arguments in bytes instead of bits here.
    constructor(blockLen, suffix, outputLen, enableXOF = false, rounds = 24) {
        super();
        this.blockLen = blockLen;
        this.suffix = suffix;
        this.outputLen = outputLen;
        this.enableXOF = enableXOF;
        this.rounds = rounds;
        this.pos = 0;
        this.posOut = 0;
        this.finished = false;
        this.destroyed = false;
        // Can be passed from user as dkLen
        _assert_js_1.default.number(outputLen);
        // 1600 = 5x5 matrix of 64bit.  1600 bits === 200 bytes
        if (0 >= this.blockLen || this.blockLen >= 200)
            throw new Error('Sha3 supports only keccak-f1600 function');
        this.state = new Uint8Array(200);
        this.state32 = (0, utils_js_1.u32)(this.state);
    }
    keccak() {
        keccakP(this.state32, this.rounds);
        this.posOut = 0;
        this.pos = 0;
    }
    update(data) {
        _assert_js_1.default.exists(this);
        const { blockLen, state } = this;
        data = (0, utils_js_1.toBytes)(data);
        const len = data.length;
        for (let pos = 0; pos < len;) {
            const take = Math.min(blockLen - this.pos, len - pos);
            for (let i = 0; i < take; i++)
                state[this.pos++] ^= data[pos++];
            if (this.pos === blockLen)
                this.keccak();
        }
        return this;
    }
    finish() {
        if (this.finished)
            return;
        this.finished = true;
        const { state, suffix, pos, blockLen } = this;
        // Do the padding
        state[pos] ^= suffix;
        if ((suffix & 0x80) !== 0 && pos === blockLen - 1)
            this.keccak();
        state[blockLen - 1] ^= 0x80;
        this.keccak();
    }
    writeInto(out) {
        _assert_js_1.default.exists(this, false);
        _assert_js_1.default.bytes(out);
        this.finish();
        const bufferOut = this.state;
        const { blockLen } = this;
        for (let pos = 0, len = out.length; pos < len;) {
            if (this.posOut >= blockLen)
                this.keccak();
            const take = Math.min(blockLen - this.posOut, len - pos);
            out.set(bufferOut.subarray(this.posOut, this.posOut + take), pos);
            this.posOut += take;
            pos += take;
        }
        return out;
    }
    xofInto(out) {
        // Sha3/Keccak usage with XOF is probably mistake, only SHAKE instances can do XOF
        if (!this.enableXOF)
            throw new Error('XOF is not possible for this instance');
        return this.writeInto(out);
    }
    xof(bytes) {
        _assert_js_1.default.number(bytes);
        return this.xofInto(new Uint8Array(bytes));
    }
    digestInto(out) {
        _assert_js_1.default.output(out, this);
        if (this.finished)
            throw new Error('digest() was already called');
        this.writeInto(out);
        this.destroy();
        return out;
    }
    digest() {
        return this.digestInto(new Uint8Array(this.outputLen));
    }
    destroy() {
        this.destroyed = true;
        this.state.fill(0);
    }
    _cloneInto(to) {
        const { blockLen, suffix, outputLen, rounds, enableXOF } = this;
        to || (to = new Keccak(blockLen, suffix, outputLen, enableXOF, rounds));
        to.state32.set(this.state32);
        to.pos = this.pos;
        to.posOut = this.posOut;
        to.finished = this.finished;
        to.rounds = rounds;
        // Suffix can change in cSHAKE
        to.suffix = suffix;
        to.outputLen = outputLen;
        to.enableXOF = enableXOF;
        to.destroyed = this.destroyed;
        return to;
    }
}
exports.Keccak = Keccak;
const gen = (suffix, blockLen, outputLen) => (0, utils_js_1.wrapConstructor)(() => new Keccak(blockLen, suffix, outputLen));
exports.sha3_224 = gen(0x06, 144, 224 / 8);
/**
 * SHA3-256 hash function
 * @param message - that would be hashed
 */
exports.sha3_256 = gen(0x06, 136, 256 / 8);
exports.sha3_384 = gen(0x06, 104, 384 / 8);
exports.sha3_512 = gen(0x06, 72, 512 / 8);
exports.keccak_224 = gen(0x01, 144, 224 / 8);
/**
 * keccak-256 hash function. Different from SHA3-256.
 * @param message - that would be hashed
 */
exports.keccak_256 = gen(0x01, 136, 256 / 8);
exports.keccak_384 = gen(0x01, 104, 384 / 8);
exports.keccak_512 = gen(0x01, 72, 512 / 8);
const genShake = (suffix, blockLen, outputLen) => (0, utils_js_1.wrapConstructorWithOpts)((opts = {}) => new Keccak(blockLen, suffix, opts.dkLen === undefined ? outputLen : opts.dkLen, true));
exports.shake128 = genShake(0x1f, 168, 128 / 8);
exports.shake256 = genShake(0x1f, 136, 256 / 8);

},{"./_assert.js":75,"./_u64.js":77,"./utils.js":82}],82:[function(require,module,exports){
"use strict";
/*! noble-hashes - MIT License (c) 2022 Paul Miller (paulmillr.com) */
Object.defineProperty(exports, "__esModule", { value: true });
exports.randomBytes = exports.wrapConstructorWithOpts = exports.wrapConstructor = exports.checkOpts = exports.Hash = exports.concatBytes = exports.toBytes = exports.utf8ToBytes = exports.asyncLoop = exports.nextTick = exports.hexToBytes = exports.bytesToHex = exports.isLE = exports.rotr = exports.createView = exports.u32 = exports.u8 = void 0;
// The import here is via the package name. This is to ensure
// that exports mapping/resolution does fall into place.
const crypto_1 = require("@noble/hashes/crypto");
// Cast array to different type
const u8 = (arr) => new Uint8Array(arr.buffer, arr.byteOffset, arr.byteLength);
exports.u8 = u8;
const u32 = (arr) => new Uint32Array(arr.buffer, arr.byteOffset, Math.floor(arr.byteLength / 4));
exports.u32 = u32;
// Cast array to view
const createView = (arr) => new DataView(arr.buffer, arr.byteOffset, arr.byteLength);
exports.createView = createView;
// The rotate right (circular right shift) operation for uint32
const rotr = (word, shift) => (word << (32 - shift)) | (word >>> shift);
exports.rotr = rotr;
exports.isLE = new Uint8Array(new Uint32Array([0x11223344]).buffer)[0] === 0x44;
// There is almost no big endian hardware, but js typed arrays uses platform specific endianness.
// So, just to be sure not to corrupt anything.
if (!exports.isLE)
    throw new Error('Non little-endian hardware is not supported');
const hexes = Array.from({ length: 256 }, (v, i) => i.toString(16).padStart(2, '0'));
/**
 * @example bytesToHex(Uint8Array.from([0xde, 0xad, 0xbe, 0xef]))
 */
function bytesToHex(uint8a) {
    // pre-caching improves the speed 6x
    if (!(uint8a instanceof Uint8Array))
        throw new Error('Uint8Array expected');
    let hex = '';
    for (let i = 0; i < uint8a.length; i++) {
        hex += hexes[uint8a[i]];
    }
    return hex;
}
exports.bytesToHex = bytesToHex;
/**
 * @example hexToBytes('deadbeef')
 */
function hexToBytes(hex) {
    if (typeof hex !== 'string') {
        throw new TypeError('hexToBytes: expected string, got ' + typeof hex);
    }
    if (hex.length % 2)
        throw new Error('hexToBytes: received invalid unpadded hex');
    const array = new Uint8Array(hex.length / 2);
    for (let i = 0; i < array.length; i++) {
        const j = i * 2;
        const hexByte = hex.slice(j, j + 2);
        const byte = Number.parseInt(hexByte, 16);
        if (Number.isNaN(byte) || byte < 0)
            throw new Error('Invalid byte sequence');
        array[i] = byte;
    }
    return array;
}
exports.hexToBytes = hexToBytes;
// There is no setImmediate in browser and setTimeout is slow. However, call to async function will return Promise
// which will be fullfiled only on next scheduler queue processing step and this is exactly what we need.
const nextTick = async () => { };
exports.nextTick = nextTick;
// Returns control to thread each 'tick' ms to avoid blocking
async function asyncLoop(iters, tick, cb) {
    let ts = Date.now();
    for (let i = 0; i < iters; i++) {
        cb(i);
        // Date.now() is not monotonic, so in case if clock goes backwards we return return control too
        const diff = Date.now() - ts;
        if (diff >= 0 && diff < tick)
            continue;
        await (0, exports.nextTick)();
        ts += diff;
    }
}
exports.asyncLoop = asyncLoop;
function utf8ToBytes(str) {
    if (typeof str !== 'string') {
        throw new TypeError(`utf8ToBytes expected string, got ${typeof str}`);
    }
    return new TextEncoder().encode(str);
}
exports.utf8ToBytes = utf8ToBytes;
function toBytes(data) {
    if (typeof data === 'string')
        data = utf8ToBytes(data);
    if (!(data instanceof Uint8Array))
        throw new TypeError(`Expected input type is Uint8Array (got ${typeof data})`);
    return data;
}
exports.toBytes = toBytes;
/**
 * Concats Uint8Array-s into one; like `Buffer.concat([buf1, buf2])`
 * @example concatBytes(buf1, buf2)
 */
function concatBytes(...arrays) {
    if (!arrays.every((a) => a instanceof Uint8Array))
        throw new Error('Uint8Array list expected');
    if (arrays.length === 1)
        return arrays[0];
    const length = arrays.reduce((a, arr) => a + arr.length, 0);
    const result = new Uint8Array(length);
    for (let i = 0, pad = 0; i < arrays.length; i++) {
        const arr = arrays[i];
        result.set(arr, pad);
        pad += arr.length;
    }
    return result;
}
exports.concatBytes = concatBytes;
// For runtime check if class implements interface
class Hash {
    // Safe version that clones internal state
    clone() {
        return this._cloneInto();
    }
}
exports.Hash = Hash;
// Check if object doens't have custom constructor (like Uint8Array/Array)
const isPlainObject = (obj) => Object.prototype.toString.call(obj) === '[object Object]' && obj.constructor === Object;
function checkOpts(defaults, opts) {
    if (opts !== undefined && (typeof opts !== 'object' || !isPlainObject(opts)))
        throw new TypeError('Options should be object or undefined');
    const merged = Object.assign(defaults, opts);
    return merged;
}
exports.checkOpts = checkOpts;
function wrapConstructor(hashConstructor) {
    const hashC = (message) => hashConstructor().update(toBytes(message)).digest();
    const tmp = hashConstructor();
    hashC.outputLen = tmp.outputLen;
    hashC.blockLen = tmp.blockLen;
    hashC.create = () => hashConstructor();
    return hashC;
}
exports.wrapConstructor = wrapConstructor;
function wrapConstructorWithOpts(hashCons) {
    const hashC = (msg, opts) => hashCons(opts).update(toBytes(msg)).digest();
    const tmp = hashCons({});
    hashC.outputLen = tmp.outputLen;
    hashC.blockLen = tmp.blockLen;
    hashC.create = (opts) => hashCons(opts);
    return hashC;
}
exports.wrapConstructorWithOpts = wrapConstructorWithOpts;
/**
 * Secure PRNG
 */
function randomBytes(bytesLength = 32) {
    if (crypto_1.crypto.web) {
        return crypto_1.crypto.web.getRandomValues(new Uint8Array(bytesLength));
    }
    else if (crypto_1.crypto.node) {
        return new Uint8Array(crypto_1.crypto.node.randomBytes(bytesLength).buffer);
    }
    else {
        throw new Error("The environment doesn't have randomBytes function");
    }
}
exports.randomBytes = randomBytes;

},{"@noble/hashes/crypto":78}],83:[function(require,module,exports){
"use strict";
/*! noble-secp256k1 - MIT License (c) 2019 Paul Miller (paulmillr.com) */
Object.defineProperty(exports, "__esModule", { value: true });
exports.utils = exports.schnorr = exports.verify = exports.signSync = exports.sign = exports.getSharedSecret = exports.recoverPublicKey = exports.getPublicKey = exports.Signature = exports.Point = exports.CURVE = void 0;
const nodeCrypto = require("crypto");
const _0n = BigInt(0);
const _1n = BigInt(1);
const _2n = BigInt(2);
const _3n = BigInt(3);
const _8n = BigInt(8);
const POW_2_256 = _2n ** BigInt(256);
const CURVE = {
    a: _0n,
    b: BigInt(7),
    P: POW_2_256 - _2n ** BigInt(32) - BigInt(977),
    n: POW_2_256 - BigInt('432420386565659656852420866394968145599'),
    h: _1n,
    Gx: BigInt('55066263022277343669578718895168534326250603453777594175500187360389116729240'),
    Gy: BigInt('32670510020758816978083085130507043184471273380659243275938904335757337482424'),
    beta: BigInt('0x7ae96a2b657c07106e64479eac3434e99cf0497512f58995c1396c28719501ee'),
};
exports.CURVE = CURVE;
function weistrass(x) {
    const { a, b } = CURVE;
    const x2 = mod(x * x);
    const x3 = mod(x2 * x);
    return mod(x3 + a * x + b);
}
const USE_ENDOMORPHISM = CURVE.a === _0n;
class JacobianPoint {
    constructor(x, y, z) {
        this.x = x;
        this.y = y;
        this.z = z;
    }
    static fromAffine(p) {
        if (!(p instanceof Point)) {
            throw new TypeError('JacobianPoint#fromAffine: expected Point');
        }
        return new JacobianPoint(p.x, p.y, _1n);
    }
    static toAffineBatch(points) {
        const toInv = invertBatch(points.map((p) => p.z));
        return points.map((p, i) => p.toAffine(toInv[i]));
    }
    static normalizeZ(points) {
        return JacobianPoint.toAffineBatch(points).map(JacobianPoint.fromAffine);
    }
    equals(other) {
        if (!(other instanceof JacobianPoint))
            throw new TypeError('JacobianPoint expected');
        const { x: X1, y: Y1, z: Z1 } = this;
        const { x: X2, y: Y2, z: Z2 } = other;
        const Z1Z1 = mod(Z1 ** _2n);
        const Z2Z2 = mod(Z2 ** _2n);
        const U1 = mod(X1 * Z2Z2);
        const U2 = mod(X2 * Z1Z1);
        const S1 = mod(mod(Y1 * Z2) * Z2Z2);
        const S2 = mod(mod(Y2 * Z1) * Z1Z1);
        return U1 === U2 && S1 === S2;
    }
    negate() {
        return new JacobianPoint(this.x, mod(-this.y), this.z);
    }
    double() {
        const { x: X1, y: Y1, z: Z1 } = this;
        const A = mod(X1 ** _2n);
        const B = mod(Y1 ** _2n);
        const C = mod(B ** _2n);
        const D = mod(_2n * (mod((X1 + B) ** _2n) - A - C));
        const E = mod(_3n * A);
        const F = mod(E ** _2n);
        const X3 = mod(F - _2n * D);
        const Y3 = mod(E * (D - X3) - _8n * C);
        const Z3 = mod(_2n * Y1 * Z1);
        return new JacobianPoint(X3, Y3, Z3);
    }
    add(other) {
        if (!(other instanceof JacobianPoint))
            throw new TypeError('JacobianPoint expected');
        const { x: X1, y: Y1, z: Z1 } = this;
        const { x: X2, y: Y2, z: Z2 } = other;
        if (X2 === _0n || Y2 === _0n)
            return this;
        if (X1 === _0n || Y1 === _0n)
            return other;
        const Z1Z1 = mod(Z1 ** _2n);
        const Z2Z2 = mod(Z2 ** _2n);
        const U1 = mod(X1 * Z2Z2);
        const U2 = mod(X2 * Z1Z1);
        const S1 = mod(mod(Y1 * Z2) * Z2Z2);
        const S2 = mod(mod(Y2 * Z1) * Z1Z1);
        const H = mod(U2 - U1);
        const r = mod(S2 - S1);
        if (H === _0n) {
            if (r === _0n) {
                return this.double();
            }
            else {
                return JacobianPoint.ZERO;
            }
        }
        const HH = mod(H ** _2n);
        const HHH = mod(H * HH);
        const V = mod(U1 * HH);
        const X3 = mod(r ** _2n - HHH - _2n * V);
        const Y3 = mod(r * (V - X3) - S1 * HHH);
        const Z3 = mod(Z1 * Z2 * H);
        return new JacobianPoint(X3, Y3, Z3);
    }
    subtract(other) {
        return this.add(other.negate());
    }
    multiplyUnsafe(scalar) {
        const P0 = JacobianPoint.ZERO;
        if (typeof scalar === 'bigint' && scalar === _0n)
            return P0;
        let n = normalizeScalar(scalar);
        if (n === _1n)
            return this;
        if (!USE_ENDOMORPHISM) {
            let p = P0;
            let d = this;
            while (n > _0n) {
                if (n & _1n)
                    p = p.add(d);
                d = d.double();
                n >>= _1n;
            }
            return p;
        }
        let { k1neg, k1, k2neg, k2 } = splitScalarEndo(n);
        let k1p = P0;
        let k2p = P0;
        let d = this;
        while (k1 > _0n || k2 > _0n) {
            if (k1 & _1n)
                k1p = k1p.add(d);
            if (k2 & _1n)
                k2p = k2p.add(d);
            d = d.double();
            k1 >>= _1n;
            k2 >>= _1n;
        }
        if (k1neg)
            k1p = k1p.negate();
        if (k2neg)
            k2p = k2p.negate();
        k2p = new JacobianPoint(mod(k2p.x * CURVE.beta), k2p.y, k2p.z);
        return k1p.add(k2p);
    }
    precomputeWindow(W) {
        const windows = USE_ENDOMORPHISM ? 128 / W + 1 : 256 / W + 1;
        const points = [];
        let p = this;
        let base = p;
        for (let window = 0; window < windows; window++) {
            base = p;
            points.push(base);
            for (let i = 1; i < 2 ** (W - 1); i++) {
                base = base.add(p);
                points.push(base);
            }
            p = base.double();
        }
        return points;
    }
    wNAF(n, affinePoint) {
        if (!affinePoint && this.equals(JacobianPoint.BASE))
            affinePoint = Point.BASE;
        const W = (affinePoint && affinePoint._WINDOW_SIZE) || 1;
        if (256 % W) {
            throw new Error('Point#wNAF: Invalid precomputation window, must be power of 2');
        }
        let precomputes = affinePoint && pointPrecomputes.get(affinePoint);
        if (!precomputes) {
            precomputes = this.precomputeWindow(W);
            if (affinePoint && W !== 1) {
                precomputes = JacobianPoint.normalizeZ(precomputes);
                pointPrecomputes.set(affinePoint, precomputes);
            }
        }
        let p = JacobianPoint.ZERO;
        let f = JacobianPoint.ZERO;
        const windows = 1 + (USE_ENDOMORPHISM ? 128 / W : 256 / W);
        const windowSize = 2 ** (W - 1);
        const mask = BigInt(2 ** W - 1);
        const maxNumber = 2 ** W;
        const shiftBy = BigInt(W);
        for (let window = 0; window < windows; window++) {
            const offset = window * windowSize;
            let wbits = Number(n & mask);
            n >>= shiftBy;
            if (wbits > windowSize) {
                wbits -= maxNumber;
                n += _1n;
            }
            if (wbits === 0) {
                let pr = precomputes[offset];
                if (window % 2)
                    pr = pr.negate();
                f = f.add(pr);
            }
            else {
                let cached = precomputes[offset + Math.abs(wbits) - 1];
                if (wbits < 0)
                    cached = cached.negate();
                p = p.add(cached);
            }
        }
        return { p, f };
    }
    multiply(scalar, affinePoint) {
        let n = normalizeScalar(scalar);
        let point;
        let fake;
        if (USE_ENDOMORPHISM) {
            const { k1neg, k1, k2neg, k2 } = splitScalarEndo(n);
            let { p: k1p, f: f1p } = this.wNAF(k1, affinePoint);
            let { p: k2p, f: f2p } = this.wNAF(k2, affinePoint);
            if (k1neg)
                k1p = k1p.negate();
            if (k2neg)
                k2p = k2p.negate();
            k2p = new JacobianPoint(mod(k2p.x * CURVE.beta), k2p.y, k2p.z);
            point = k1p.add(k2p);
            fake = f1p.add(f2p);
        }
        else {
            const { p, f } = this.wNAF(n, affinePoint);
            point = p;
            fake = f;
        }
        return JacobianPoint.normalizeZ([point, fake])[0];
    }
    toAffine(invZ = invert(this.z)) {
        const { x, y, z } = this;
        const iz1 = invZ;
        const iz2 = mod(iz1 * iz1);
        const iz3 = mod(iz2 * iz1);
        const ax = mod(x * iz2);
        const ay = mod(y * iz3);
        const zz = mod(z * iz1);
        if (zz !== _1n)
            throw new Error('invZ was invalid');
        return new Point(ax, ay);
    }
}
JacobianPoint.BASE = new JacobianPoint(CURVE.Gx, CURVE.Gy, _1n);
JacobianPoint.ZERO = new JacobianPoint(_0n, _1n, _0n);
const pointPrecomputes = new WeakMap();
class Point {
    constructor(x, y) {
        this.x = x;
        this.y = y;
    }
    _setWindowSize(windowSize) {
        this._WINDOW_SIZE = windowSize;
        pointPrecomputes.delete(this);
    }
    static fromCompressedHex(bytes) {
        const isShort = bytes.length === 32;
        const x = bytesToNumber(isShort ? bytes : bytes.subarray(1));
        if (!isValidFieldElement(x))
            throw new Error('Point is not on curve');
        const y2 = weistrass(x);
        let y = sqrtMod(y2);
        const isYOdd = (y & _1n) === _1n;
        if (isShort) {
            if (isYOdd)
                y = mod(-y);
        }
        else {
            const isFirstByteOdd = (bytes[0] & 1) === 1;
            if (isFirstByteOdd !== isYOdd)
                y = mod(-y);
        }
        const point = new Point(x, y);
        point.assertValidity();
        return point;
    }
    static fromUncompressedHex(bytes) {
        const x = bytesToNumber(bytes.subarray(1, 33));
        const y = bytesToNumber(bytes.subarray(33, 65));
        const point = new Point(x, y);
        point.assertValidity();
        return point;
    }
    static fromHex(hex) {
        const bytes = ensureBytes(hex);
        const len = bytes.length;
        const header = bytes[0];
        if (len === 32 || (len === 33 && (header === 0x02 || header === 0x03))) {
            return this.fromCompressedHex(bytes);
        }
        if (len === 65 && header === 0x04)
            return this.fromUncompressedHex(bytes);
        throw new Error(`Point.fromHex: received invalid point. Expected 32-33 compressed bytes or 65 uncompressed bytes, not ${len}`);
    }
    static fromPrivateKey(privateKey) {
        return Point.BASE.multiply(normalizePrivateKey(privateKey));
    }
    static fromSignature(msgHash, signature, recovery) {
        msgHash = ensureBytes(msgHash);
        const h = truncateHash(msgHash);
        const { r, s } = normalizeSignature(signature);
        if (recovery !== 0 && recovery !== 1) {
            throw new Error('Cannot recover signature: invalid recovery bit');
        }
        const prefix = recovery & 1 ? '03' : '02';
        const R = Point.fromHex(prefix + numTo32bStr(r));
        const { n } = CURVE;
        const rinv = invert(r, n);
        const u1 = mod(-h * rinv, n);
        const u2 = mod(s * rinv, n);
        const Q = Point.BASE.multiplyAndAddUnsafe(R, u1, u2);
        if (!Q)
            throw new Error('Cannot recover signature: point at infinify');
        Q.assertValidity();
        return Q;
    }
    toRawBytes(isCompressed = false) {
        return hexToBytes(this.toHex(isCompressed));
    }
    toHex(isCompressed = false) {
        const x = numTo32bStr(this.x);
        if (isCompressed) {
            const prefix = this.y & _1n ? '03' : '02';
            return `${prefix}${x}`;
        }
        else {
            return `04${x}${numTo32bStr(this.y)}`;
        }
    }
    toHexX() {
        return this.toHex(true).slice(2);
    }
    toRawX() {
        return this.toRawBytes(true).slice(1);
    }
    assertValidity() {
        const msg = 'Point is not on elliptic curve';
        const { x, y } = this;
        if (!isValidFieldElement(x) || !isValidFieldElement(y))
            throw new Error(msg);
        const left = mod(y * y);
        const right = weistrass(x);
        if (mod(left - right) !== _0n)
            throw new Error(msg);
    }
    equals(other) {
        return this.x === other.x && this.y === other.y;
    }
    negate() {
        return new Point(this.x, mod(-this.y));
    }
    double() {
        return JacobianPoint.fromAffine(this).double().toAffine();
    }
    add(other) {
        return JacobianPoint.fromAffine(this).add(JacobianPoint.fromAffine(other)).toAffine();
    }
    subtract(other) {
        return this.add(other.negate());
    }
    multiply(scalar) {
        return JacobianPoint.fromAffine(this).multiply(scalar, this).toAffine();
    }
    multiplyAndAddUnsafe(Q, a, b) {
        const P = JacobianPoint.fromAffine(this);
        const aP = a === _0n || a === _1n || this !== Point.BASE ? P.multiplyUnsafe(a) : P.multiply(a);
        const bQ = JacobianPoint.fromAffine(Q).multiplyUnsafe(b);
        const sum = aP.add(bQ);
        return sum.equals(JacobianPoint.ZERO) ? undefined : sum.toAffine();
    }
}
exports.Point = Point;
Point.BASE = new Point(CURVE.Gx, CURVE.Gy);
Point.ZERO = new Point(_0n, _0n);
function sliceDER(s) {
    return Number.parseInt(s[0], 16) >= 8 ? '00' + s : s;
}
function parseDERInt(data) {
    if (data.length < 2 || data[0] !== 0x02) {
        throw new Error(`Invalid signature integer tag: ${bytesToHex(data)}`);
    }
    const len = data[1];
    const res = data.subarray(2, len + 2);
    if (!len || res.length !== len) {
        throw new Error(`Invalid signature integer: wrong length`);
    }
    if (res[0] === 0x00 && res[1] <= 0x7f) {
        throw new Error('Invalid signature integer: trailing length');
    }
    return { data: bytesToNumber(res), left: data.subarray(len + 2) };
}
function parseDERSignature(data) {
    if (data.length < 2 || data[0] != 0x30) {
        throw new Error(`Invalid signature tag: ${bytesToHex(data)}`);
    }
    if (data[1] !== data.length - 2) {
        throw new Error('Invalid signature: incorrect length');
    }
    const { data: r, left: sBytes } = parseDERInt(data.subarray(2));
    const { data: s, left: rBytesLeft } = parseDERInt(sBytes);
    if (rBytesLeft.length) {
        throw new Error(`Invalid signature: left bytes after parsing: ${bytesToHex(rBytesLeft)}`);
    }
    return { r, s };
}
class Signature {
    constructor(r, s) {
        this.r = r;
        this.s = s;
        this.assertValidity();
    }
    static fromCompact(hex) {
        const arr = isUint8a(hex);
        const name = 'Signature.fromCompact';
        if (typeof hex !== 'string' && !arr)
            throw new TypeError(`${name}: Expected string or Uint8Array`);
        const str = arr ? bytesToHex(hex) : hex;
        if (str.length !== 128)
            throw new Error(`${name}: Expected 64-byte hex`);
        return new Signature(hexToNumber(str.slice(0, 64)), hexToNumber(str.slice(64, 128)));
    }
    static fromDER(hex) {
        const arr = isUint8a(hex);
        if (typeof hex !== 'string' && !arr)
            throw new TypeError(`Signature.fromDER: Expected string or Uint8Array`);
        const { r, s } = parseDERSignature(arr ? hex : hexToBytes(hex));
        return new Signature(r, s);
    }
    static fromHex(hex) {
        return this.fromDER(hex);
    }
    assertValidity() {
        const { r, s } = this;
        if (!isWithinCurveOrder(r))
            throw new Error('Invalid Signature: r must be 0 < r < n');
        if (!isWithinCurveOrder(s))
            throw new Error('Invalid Signature: s must be 0 < s < n');
    }
    hasHighS() {
        const HALF = CURVE.n >> _1n;
        return this.s > HALF;
    }
    normalizeS() {
        return this.hasHighS() ? new Signature(this.r, CURVE.n - this.s) : this;
    }
    toDERRawBytes(isCompressed = false) {
        return hexToBytes(this.toDERHex(isCompressed));
    }
    toDERHex(isCompressed = false) {
        const sHex = sliceDER(numberToHexUnpadded(this.s));
        if (isCompressed)
            return sHex;
        const rHex = sliceDER(numberToHexUnpadded(this.r));
        const rLen = numberToHexUnpadded(rHex.length / 2);
        const sLen = numberToHexUnpadded(sHex.length / 2);
        const length = numberToHexUnpadded(rHex.length / 2 + sHex.length / 2 + 4);
        return `30${length}02${rLen}${rHex}02${sLen}${sHex}`;
    }
    toRawBytes() {
        return this.toDERRawBytes();
    }
    toHex() {
        return this.toDERHex();
    }
    toCompactRawBytes() {
        return hexToBytes(this.toCompactHex());
    }
    toCompactHex() {
        return numTo32bStr(this.r) + numTo32bStr(this.s);
    }
}
exports.Signature = Signature;
function concatBytes(...arrays) {
    if (!arrays.every(isUint8a))
        throw new Error('Uint8Array list expected');
    if (arrays.length === 1)
        return arrays[0];
    const length = arrays.reduce((a, arr) => a + arr.length, 0);
    const result = new Uint8Array(length);
    for (let i = 0, pad = 0; i < arrays.length; i++) {
        const arr = arrays[i];
        result.set(arr, pad);
        pad += arr.length;
    }
    return result;
}
function isUint8a(bytes) {
    return bytes instanceof Uint8Array;
}
const hexes = Array.from({ length: 256 }, (v, i) => i.toString(16).padStart(2, '0'));
function bytesToHex(uint8a) {
    if (!(uint8a instanceof Uint8Array))
        throw new Error('Expected Uint8Array');
    let hex = '';
    for (let i = 0; i < uint8a.length; i++) {
        hex += hexes[uint8a[i]];
    }
    return hex;
}
function numTo32bStr(num) {
    if (num > POW_2_256)
        throw new Error('Expected number < 2^256');
    return num.toString(16).padStart(64, '0');
}
function numTo32b(num) {
    return hexToBytes(numTo32bStr(num));
}
function numberToHexUnpadded(num) {
    const hex = num.toString(16);
    return hex.length & 1 ? `0${hex}` : hex;
}
function hexToNumber(hex) {
    if (typeof hex !== 'string') {
        throw new TypeError('hexToNumber: expected string, got ' + typeof hex);
    }
    return BigInt(`0x${hex}`);
}
function hexToBytes(hex) {
    if (typeof hex !== 'string') {
        throw new TypeError('hexToBytes: expected string, got ' + typeof hex);
    }
    if (hex.length % 2)
        throw new Error('hexToBytes: received invalid unpadded hex' + hex.length);
    const array = new Uint8Array(hex.length / 2);
    for (let i = 0; i < array.length; i++) {
        const j = i * 2;
        const hexByte = hex.slice(j, j + 2);
        const byte = Number.parseInt(hexByte, 16);
        if (Number.isNaN(byte) || byte < 0)
            throw new Error('Invalid byte sequence');
        array[i] = byte;
    }
    return array;
}
function bytesToNumber(bytes) {
    return hexToNumber(bytesToHex(bytes));
}
function ensureBytes(hex) {
    return hex instanceof Uint8Array ? Uint8Array.from(hex) : hexToBytes(hex);
}
function normalizeScalar(num) {
    if (typeof num === 'number' && Number.isSafeInteger(num) && num > 0)
        return BigInt(num);
    if (typeof num === 'bigint' && isWithinCurveOrder(num))
        return num;
    throw new TypeError('Expected valid private scalar: 0 < scalar < curve.n');
}
function mod(a, b = CURVE.P) {
    const result = a % b;
    return result >= _0n ? result : b + result;
}
function pow2(x, power) {
    const { P } = CURVE;
    let res = x;
    while (power-- > _0n) {
        res *= res;
        res %= P;
    }
    return res;
}
function sqrtMod(x) {
    const { P } = CURVE;
    const _6n = BigInt(6);
    const _11n = BigInt(11);
    const _22n = BigInt(22);
    const _23n = BigInt(23);
    const _44n = BigInt(44);
    const _88n = BigInt(88);
    const b2 = (x * x * x) % P;
    const b3 = (b2 * b2 * x) % P;
    const b6 = (pow2(b3, _3n) * b3) % P;
    const b9 = (pow2(b6, _3n) * b3) % P;
    const b11 = (pow2(b9, _2n) * b2) % P;
    const b22 = (pow2(b11, _11n) * b11) % P;
    const b44 = (pow2(b22, _22n) * b22) % P;
    const b88 = (pow2(b44, _44n) * b44) % P;
    const b176 = (pow2(b88, _88n) * b88) % P;
    const b220 = (pow2(b176, _44n) * b44) % P;
    const b223 = (pow2(b220, _3n) * b3) % P;
    const t1 = (pow2(b223, _23n) * b22) % P;
    const t2 = (pow2(t1, _6n) * b2) % P;
    return pow2(t2, _2n);
}
function invert(number, modulo = CURVE.P) {
    if (number === _0n || modulo <= _0n) {
        throw new Error(`invert: expected positive integers, got n=${number} mod=${modulo}`);
    }
    let a = mod(number, modulo);
    let b = modulo;
    let x = _0n, y = _1n, u = _1n, v = _0n;
    while (a !== _0n) {
        const q = b / a;
        const r = b % a;
        const m = x - u * q;
        const n = y - v * q;
        b = a, a = r, x = u, y = v, u = m, v = n;
    }
    const gcd = b;
    if (gcd !== _1n)
        throw new Error('invert: does not exist');
    return mod(x, modulo);
}
function invertBatch(nums, p = CURVE.P) {
    const scratch = new Array(nums.length);
    const lastMultiplied = nums.reduce((acc, num, i) => {
        if (num === _0n)
            return acc;
        scratch[i] = acc;
        return mod(acc * num, p);
    }, _1n);
    const inverted = invert(lastMultiplied, p);
    nums.reduceRight((acc, num, i) => {
        if (num === _0n)
            return acc;
        scratch[i] = mod(acc * scratch[i], p);
        return mod(acc * num, p);
    }, inverted);
    return scratch;
}
const divNearest = (a, b) => (a + b / _2n) / b;
const POW_2_128 = _2n ** BigInt(128);
function splitScalarEndo(k) {
    const { n } = CURVE;
    const a1 = BigInt('0x3086d221a7d46bcde86c90e49284eb15');
    const b1 = -_1n * BigInt('0xe4437ed6010e88286f547fa90abfe4c3');
    const a2 = BigInt('0x114ca50f7a8e2f3f657c1108d9d44cfd8');
    const b2 = a1;
    const c1 = divNearest(b2 * k, n);
    const c2 = divNearest(-b1 * k, n);
    let k1 = mod(k - c1 * a1 - c2 * a2, n);
    let k2 = mod(-c1 * b1 - c2 * b2, n);
    const k1neg = k1 > POW_2_128;
    const k2neg = k2 > POW_2_128;
    if (k1neg)
        k1 = n - k1;
    if (k2neg)
        k2 = n - k2;
    if (k1 > POW_2_128 || k2 > POW_2_128) {
        throw new Error('splitScalarEndo: Endomorphism failed, k=' + k);
    }
    return { k1neg, k1, k2neg, k2 };
}
function truncateHash(hash) {
    const { n } = CURVE;
    const byteLength = hash.length;
    const delta = byteLength * 8 - 256;
    let h = bytesToNumber(hash);
    if (delta > 0)
        h = h >> BigInt(delta);
    if (h >= n)
        h -= n;
    return h;
}
class HmacDrbg {
    constructor() {
        this.v = new Uint8Array(32).fill(1);
        this.k = new Uint8Array(32).fill(0);
        this.counter = 0;
    }
    hmac(...values) {
        return exports.utils.hmacSha256(this.k, ...values);
    }
    hmacSync(...values) {
        if (typeof exports.utils.hmacSha256Sync !== 'function')
            throw new Error('utils.hmacSha256Sync is undefined, you need to set it');
        const res = exports.utils.hmacSha256Sync(this.k, ...values);
        if (res instanceof Promise)
            throw new Error('To use sync sign(), ensure utils.hmacSha256 is sync');
        return res;
    }
    incr() {
        if (this.counter >= 1000) {
            throw new Error('Tried 1,000 k values for sign(), all were invalid');
        }
        this.counter += 1;
    }
    async reseed(seed = new Uint8Array()) {
        this.k = await this.hmac(this.v, Uint8Array.from([0x00]), seed);
        this.v = await this.hmac(this.v);
        if (seed.length === 0)
            return;
        this.k = await this.hmac(this.v, Uint8Array.from([0x01]), seed);
        this.v = await this.hmac(this.v);
    }
    reseedSync(seed = new Uint8Array()) {
        this.k = this.hmacSync(this.v, Uint8Array.from([0x00]), seed);
        this.v = this.hmacSync(this.v);
        if (seed.length === 0)
            return;
        this.k = this.hmacSync(this.v, Uint8Array.from([0x01]), seed);
        this.v = this.hmacSync(this.v);
    }
    async generate() {
        this.incr();
        this.v = await this.hmac(this.v);
        return this.v;
    }
    generateSync() {
        this.incr();
        this.v = this.hmacSync(this.v);
        return this.v;
    }
}
function isWithinCurveOrder(num) {
    return _0n < num && num < CURVE.n;
}
function isValidFieldElement(num) {
    return _0n < num && num < CURVE.P;
}
function kmdToSig(kBytes, m, d) {
    const k = bytesToNumber(kBytes);
    if (!isWithinCurveOrder(k))
        return;
    const { n } = CURVE;
    const q = Point.BASE.multiply(k);
    const r = mod(q.x, n);
    if (r === _0n)
        return;
    const s = mod(invert(k, n) * mod(m + d * r, n), n);
    if (s === _0n)
        return;
    const sig = new Signature(r, s);
    const recovery = (q.x === sig.r ? 0 : 2) | Number(q.y & _1n);
    return { sig, recovery };
}
function normalizePrivateKey(key) {
    let num;
    if (typeof key === 'bigint') {
        num = key;
    }
    else if (typeof key === 'number' && Number.isSafeInteger(key) && key > 0) {
        num = BigInt(key);
    }
    else if (typeof key === 'string') {
        if (key.length !== 64)
            throw new Error('Expected 32 bytes of private key');
        num = hexToNumber(key);
    }
    else if (isUint8a(key)) {
        if (key.length !== 32)
            throw new Error('Expected 32 bytes of private key');
        num = bytesToNumber(key);
    }
    else {
        throw new TypeError('Expected valid private key');
    }
    if (!isWithinCurveOrder(num))
        throw new Error('Expected private key: 0 < key < n');
    return num;
}
function normalizePublicKey(publicKey) {
    if (publicKey instanceof Point) {
        publicKey.assertValidity();
        return publicKey;
    }
    else {
        return Point.fromHex(publicKey);
    }
}
function normalizeSignature(signature) {
    if (signature instanceof Signature) {
        signature.assertValidity();
        return signature;
    }
    try {
        return Signature.fromDER(signature);
    }
    catch (error) {
        return Signature.fromCompact(signature);
    }
}
function getPublicKey(privateKey, isCompressed = false) {
    return Point.fromPrivateKey(privateKey).toRawBytes(isCompressed);
}
exports.getPublicKey = getPublicKey;
function recoverPublicKey(msgHash, signature, recovery, isCompressed = false) {
    return Point.fromSignature(msgHash, signature, recovery).toRawBytes(isCompressed);
}
exports.recoverPublicKey = recoverPublicKey;
function isPub(item) {
    const arr = isUint8a(item);
    const str = typeof item === 'string';
    const len = (arr || str) && item.length;
    if (arr)
        return len === 33 || len === 65;
    if (str)
        return len === 66 || len === 130;
    if (item instanceof Point)
        return true;
    return false;
}
function getSharedSecret(privateA, publicB, isCompressed = false) {
    if (isPub(privateA))
        throw new TypeError('getSharedSecret: first arg must be private key');
    if (!isPub(publicB))
        throw new TypeError('getSharedSecret: second arg must be public key');
    const b = normalizePublicKey(publicB);
    b.assertValidity();
    return b.multiply(normalizePrivateKey(privateA)).toRawBytes(isCompressed);
}
exports.getSharedSecret = getSharedSecret;
function bits2int(bytes) {
    const slice = bytes.length > 32 ? bytes.slice(0, 32) : bytes;
    return bytesToNumber(slice);
}
function bits2octets(bytes) {
    const z1 = bits2int(bytes);
    const z2 = mod(z1, CURVE.n);
    return int2octets(z2 < _0n ? z1 : z2);
}
function int2octets(num) {
    if (typeof num !== 'bigint')
        throw new Error('Expected bigint');
    const hex = numTo32bStr(num);
    return hexToBytes(hex);
}
function initSigArgs(msgHash, privateKey, extraEntropy) {
    if (msgHash == null)
        throw new Error(`sign: expected valid message hash, not "${msgHash}"`);
    const h1 = ensureBytes(msgHash);
    const d = normalizePrivateKey(privateKey);
    const seedArgs = [int2octets(d), bits2octets(h1)];
    if (extraEntropy != null) {
        if (extraEntropy === true)
            extraEntropy = exports.utils.randomBytes(32);
        const e = ensureBytes(extraEntropy);
        if (e.length !== 32)
            throw new Error('sign: Expected 32 bytes of extra data');
        seedArgs.push(e);
    }
    const seed = concatBytes(...seedArgs);
    const m = bits2int(h1);
    return { seed, m, d };
}
function finalizeSig(recSig, opts) {
    let { sig, recovery } = recSig;
    const { canonical, der, recovered } = Object.assign({ canonical: true, der: true }, opts);
    if (canonical && sig.hasHighS()) {
        sig = sig.normalizeS();
        recovery ^= 1;
    }
    const hashed = der ? sig.toDERRawBytes() : sig.toCompactRawBytes();
    return recovered ? [hashed, recovery] : hashed;
}
async function sign(msgHash, privKey, opts = {}) {
    const { seed, m, d } = initSigArgs(msgHash, privKey, opts.extraEntropy);
    let sig;
    const drbg = new HmacDrbg();
    await drbg.reseed(seed);
    while (!(sig = kmdToSig(await drbg.generate(), m, d)))
        await drbg.reseed();
    return finalizeSig(sig, opts);
}
exports.sign = sign;
function signSync(msgHash, privKey, opts = {}) {
    const { seed, m, d } = initSigArgs(msgHash, privKey, opts.extraEntropy);
    let sig;
    const drbg = new HmacDrbg();
    drbg.reseedSync(seed);
    while (!(sig = kmdToSig(drbg.generateSync(), m, d)))
        drbg.reseedSync();
    return finalizeSig(sig, opts);
}
exports.signSync = signSync;
const vopts = { strict: true };
function verify(signature, msgHash, publicKey, opts = vopts) {
    let sig;
    try {
        sig = normalizeSignature(signature);
        msgHash = ensureBytes(msgHash);
    }
    catch (error) {
        return false;
    }
    const { r, s } = sig;
    if (opts.strict && sig.hasHighS())
        return false;
    const h = truncateHash(msgHash);
    let P;
    try {
        P = normalizePublicKey(publicKey);
    }
    catch (error) {
        return false;
    }
    const { n } = CURVE;
    const sinv = invert(s, n);
    const u1 = mod(h * sinv, n);
    const u2 = mod(r * sinv, n);
    const R = Point.BASE.multiplyAndAddUnsafe(P, u1, u2);
    if (!R)
        return false;
    const v = mod(R.x, n);
    return v === r;
}
exports.verify = verify;
function finalizeSchnorrChallenge(ch) {
    return mod(bytesToNumber(ch), CURVE.n);
}
function hasEvenY(point) {
    return (point.y & _1n) === _0n;
}
class SchnorrSignature {
    constructor(r, s) {
        this.r = r;
        this.s = s;
        this.assertValidity();
    }
    static fromHex(hex) {
        const bytes = ensureBytes(hex);
        if (bytes.length !== 64)
            throw new TypeError(`SchnorrSignature.fromHex: expected 64 bytes, not ${bytes.length}`);
        const r = bytesToNumber(bytes.subarray(0, 32));
        const s = bytesToNumber(bytes.subarray(32, 64));
        return new SchnorrSignature(r, s);
    }
    assertValidity() {
        const { r, s } = this;
        if (!isValidFieldElement(r) || !isWithinCurveOrder(s))
            throw new Error('Invalid signature');
    }
    toHex() {
        return numTo32bStr(this.r) + numTo32bStr(this.s);
    }
    toRawBytes() {
        return hexToBytes(this.toHex());
    }
}
function schnorrGetPublicKey(privateKey) {
    return Point.fromPrivateKey(privateKey).toRawX();
}
function initSchnorrSigArgs(message, privateKey, auxRand) {
    if (message == null)
        throw new TypeError(`sign: Expected valid message, not "${message}"`);
    const m = ensureBytes(message);
    const d0 = normalizePrivateKey(privateKey);
    const rand = ensureBytes(auxRand);
    if (rand.length !== 32)
        throw new TypeError('sign: Expected 32 bytes of aux randomness');
    const P = Point.fromPrivateKey(d0);
    const px = P.toRawX();
    const d = hasEvenY(P) ? d0 : CURVE.n - d0;
    return { m, P, px, d, rand };
}
function initSchnorrNonce(d, t0h) {
    return numTo32b(d ^ bytesToNumber(t0h));
}
function finalizeSchnorrNonce(k0h) {
    const k0 = mod(bytesToNumber(k0h), CURVE.n);
    if (k0 === _0n)
        throw new Error('sign: Creation of signature failed. k is zero');
    const R = Point.fromPrivateKey(k0);
    const rx = R.toRawX();
    const k = hasEvenY(R) ? k0 : CURVE.n - k0;
    return { R, rx, k };
}
function finalizeSchnorrSig(R, k, e, d) {
    return new SchnorrSignature(R.x, mod(k + e * d, CURVE.n)).toRawBytes();
}
async function schnorrSign(message, privateKey, auxRand = exports.utils.randomBytes()) {
    const { m, px, d, rand } = initSchnorrSigArgs(message, privateKey, auxRand);
    const t = initSchnorrNonce(d, await exports.utils.taggedHash(TAGS.aux, rand));
    const { R, rx, k } = finalizeSchnorrNonce(await exports.utils.taggedHash(TAGS.nonce, t, px, m));
    const e = finalizeSchnorrChallenge(await exports.utils.taggedHash(TAGS.challenge, rx, px, m));
    const sig = finalizeSchnorrSig(R, k, e, d);
    const isValid = await schnorrVerify(sig, m, px);
    if (!isValid)
        throw new Error('sign: Invalid signature produced');
    return sig;
}
function schnorrSignSync(message, privateKey, auxRand = exports.utils.randomBytes()) {
    const { m, px, d, rand } = initSchnorrSigArgs(message, privateKey, auxRand);
    const t = initSchnorrNonce(d, exports.utils.taggedHashSync(TAGS.aux, rand));
    const { R, rx, k } = finalizeSchnorrNonce(exports.utils.taggedHashSync(TAGS.nonce, t, px, m));
    const e = finalizeSchnorrChallenge(exports.utils.taggedHashSync(TAGS.challenge, rx, px, m));
    const sig = finalizeSchnorrSig(R, k, e, d);
    const isValid = schnorrVerifySync(sig, m, px);
    if (!isValid)
        throw new Error('sign: Invalid signature produced');
    return sig;
}
function initSchnorrVerify(signature, message, publicKey) {
    const raw = signature instanceof SchnorrSignature;
    const sig = raw ? signature : SchnorrSignature.fromHex(signature);
    if (raw)
        sig.assertValidity();
    return {
        ...sig,
        m: ensureBytes(message),
        P: normalizePublicKey(publicKey),
    };
}
function finalizeSchnorrVerify(r, P, s, e) {
    const R = Point.BASE.multiplyAndAddUnsafe(P, normalizePrivateKey(s), mod(-e, CURVE.n));
    if (!R || !hasEvenY(R) || R.x !== r)
        return false;
    return true;
}
async function schnorrVerify(signature, message, publicKey) {
    try {
        const { r, s, m, P } = initSchnorrVerify(signature, message, publicKey);
        const e = finalizeSchnorrChallenge(await exports.utils.taggedHash(TAGS.challenge, numTo32b(r), P.toRawX(), m));
        return finalizeSchnorrVerify(r, P, s, e);
    }
    catch (error) {
        return false;
    }
}
function schnorrVerifySync(signature, message, publicKey) {
    try {
        const { r, s, m, P } = initSchnorrVerify(signature, message, publicKey);
        const e = finalizeSchnorrChallenge(exports.utils.taggedHashSync(TAGS.challenge, numTo32b(r), P.toRawX(), m));
        return finalizeSchnorrVerify(r, P, s, e);
    }
    catch (error) {
        return false;
    }
}
exports.schnorr = {
    Signature: SchnorrSignature,
    getPublicKey: schnorrGetPublicKey,
    sign: schnorrSign,
    verify: schnorrVerify,
    signSync: schnorrSignSync,
    verifySync: schnorrVerifySync,
};
Point.BASE._setWindowSize(8);
const crypto = {
    node: nodeCrypto,
    web: typeof self === 'object' && 'crypto' in self ? self.crypto : undefined,
};
const TAGS = {
    challenge: 'BIP0340/challenge',
    aux: 'BIP0340/aux',
    nonce: 'BIP0340/nonce',
};
const TAGGED_HASH_PREFIXES = {};
exports.utils = {
    isValidPrivateKey(privateKey) {
        try {
            normalizePrivateKey(privateKey);
            return true;
        }
        catch (error) {
            return false;
        }
    },
    privateAdd: (privateKey, tweak) => {
        const p = normalizePrivateKey(privateKey);
        const t = normalizePrivateKey(tweak);
        return numTo32b(mod(p + t, CURVE.n));
    },
    privateNegate: (privateKey) => {
        const p = normalizePrivateKey(privateKey);
        return numTo32b(CURVE.n - p);
    },
    pointAddScalar: (p, tweak, isCompressed) => {
        const P = Point.fromHex(p);
        const t = normalizePrivateKey(tweak);
        const Q = Point.BASE.multiplyAndAddUnsafe(P, t, _1n);
        if (!Q)
            throw new Error('Tweaked point at infinity');
        return Q.toRawBytes(isCompressed);
    },
    pointMultiply: (p, tweak, isCompressed) => {
        const P = Point.fromHex(p);
        const t = bytesToNumber(ensureBytes(tweak));
        return P.multiply(t).toRawBytes(isCompressed);
    },
    hashToPrivateKey: (hash) => {
        hash = ensureBytes(hash);
        if (hash.length < 40 || hash.length > 1024)
            throw new Error('Expected 40-1024 bytes of private key as per FIPS 186');
        const num = mod(bytesToNumber(hash), CURVE.n - _1n) + _1n;
        return numTo32b(num);
    },
    randomBytes: (bytesLength = 32) => {
        if (crypto.web) {
            return crypto.web.getRandomValues(new Uint8Array(bytesLength));
        }
        else if (crypto.node) {
            const { randomBytes } = crypto.node;
            return Uint8Array.from(randomBytes(bytesLength));
        }
        else {
            throw new Error("The environment doesn't have randomBytes function");
        }
    },
    randomPrivateKey: () => {
        return exports.utils.hashToPrivateKey(exports.utils.randomBytes(40));
    },
    bytesToHex,
    hexToBytes,
    concatBytes,
    mod,
    invert,
    sha256: async (...messages) => {
        if (crypto.web) {
            const buffer = await crypto.web.subtle.digest('SHA-256', concatBytes(...messages));
            return new Uint8Array(buffer);
        }
        else if (crypto.node) {
            const { createHash } = crypto.node;
            const hash = createHash('sha256');
            messages.forEach((m) => hash.update(m));
            return Uint8Array.from(hash.digest());
        }
        else {
            throw new Error("The environment doesn't have sha256 function");
        }
    },
    hmacSha256: async (key, ...messages) => {
        if (crypto.web) {
            const ckey = await crypto.web.subtle.importKey('raw', key, { name: 'HMAC', hash: { name: 'SHA-256' } }, false, ['sign']);
            const message = concatBytes(...messages);
            const buffer = await crypto.web.subtle.sign('HMAC', ckey, message);
            return new Uint8Array(buffer);
        }
        else if (crypto.node) {
            const { createHmac } = crypto.node;
            const hash = createHmac('sha256', key);
            messages.forEach((m) => hash.update(m));
            return Uint8Array.from(hash.digest());
        }
        else {
            throw new Error("The environment doesn't have hmac-sha256 function");
        }
    },
    sha256Sync: undefined,
    hmacSha256Sync: undefined,
    taggedHash: async (tag, ...messages) => {
        let tagP = TAGGED_HASH_PREFIXES[tag];
        if (tagP === undefined) {
            const tagH = await exports.utils.sha256(Uint8Array.from(tag, (c) => c.charCodeAt(0)));
            tagP = concatBytes(tagH, tagH);
            TAGGED_HASH_PREFIXES[tag] = tagP;
        }
        return exports.utils.sha256(tagP, ...messages);
    },
    taggedHashSync: (tag, ...messages) => {
        if (typeof exports.utils.sha256Sync !== 'function')
            throw new Error('utils.sha256Sync is undefined, you need to set it');
        let tagP = TAGGED_HASH_PREFIXES[tag];
        if (tagP === undefined) {
            const tagH = exports.utils.sha256Sync(Uint8Array.from(tag, (c) => c.charCodeAt(0)));
            tagP = concatBytes(tagH, tagH);
            TAGGED_HASH_PREFIXES[tag] = tagP;
        }
        return exports.utils.sha256Sync(tagP, ...messages);
    },
    precompute(windowSize = 8, point = Point.BASE) {
        const cached = point === Point.BASE ? point : new Point(point.x, point.y);
        cached._setWindowSize(windowSize);
        cached.multiply(_3n);
        return cached;
    },
};

},{"crypto":88}],84:[function(require,module,exports){
/*! crc32.js (C) 2014-present SheetJS -- http://sheetjs.com */
/* vim: set ts=2: */
/*exported CRC32 */
var CRC32;
(function (factory) {
	/*jshint ignore:start */
	/*eslint-disable */
	if(typeof DO_NOT_EXPORT_CRC === 'undefined') {
		if('object' === typeof exports) {
			factory(exports);
		} else if ('function' === typeof define && define.amd) {
			define(function () {
				var module = {};
				factory(module);
				return module;
			});
		} else {
			factory(CRC32 = {});
		}
	} else {
		factory(CRC32 = {});
	}
	/*eslint-enable */
	/*jshint ignore:end */
}(function(CRC32) {
CRC32.version = '1.2.2';
/*global Int32Array */
function signed_crc_table() {
	var c = 0, table = new Array(256);

	for(var n =0; n != 256; ++n){
		c = n;
		c = ((c&1) ? (-306674912 ^ (c >>> 1)) : (c >>> 1));
		c = ((c&1) ? (-306674912 ^ (c >>> 1)) : (c >>> 1));
		c = ((c&1) ? (-306674912 ^ (c >>> 1)) : (c >>> 1));
		c = ((c&1) ? (-306674912 ^ (c >>> 1)) : (c >>> 1));
		c = ((c&1) ? (-306674912 ^ (c >>> 1)) : (c >>> 1));
		c = ((c&1) ? (-306674912 ^ (c >>> 1)) : (c >>> 1));
		c = ((c&1) ? (-306674912 ^ (c >>> 1)) : (c >>> 1));
		c = ((c&1) ? (-306674912 ^ (c >>> 1)) : (c >>> 1));
		table[n] = c;
	}

	return typeof Int32Array !== 'undefined' ? new Int32Array(table) : table;
}

var T0 = signed_crc_table();
function slice_by_16_tables(T) {
	var c = 0, v = 0, n = 0, table = typeof Int32Array !== 'undefined' ? new Int32Array(4096) : new Array(4096) ;

	for(n = 0; n != 256; ++n) table[n] = T[n];
	for(n = 0; n != 256; ++n) {
		v = T[n];
		for(c = 256 + n; c < 4096; c += 256) v = table[c] = (v >>> 8) ^ T[v & 0xFF];
	}
	var out = [];
	for(n = 1; n != 16; ++n) out[n - 1] = typeof Int32Array !== 'undefined' ? table.subarray(n * 256, n * 256 + 256) : table.slice(n * 256, n * 256 + 256);
	return out;
}
var TT = slice_by_16_tables(T0);
var T1 = TT[0],  T2 = TT[1],  T3 = TT[2],  T4 = TT[3],  T5 = TT[4];
var T6 = TT[5],  T7 = TT[6],  T8 = TT[7],  T9 = TT[8],  Ta = TT[9];
var Tb = TT[10], Tc = TT[11], Td = TT[12], Te = TT[13], Tf = TT[14];
function crc32_bstr(bstr, seed) {
	var C = seed ^ -1;
	for(var i = 0, L = bstr.length; i < L;) C = (C>>>8) ^ T0[(C^bstr.charCodeAt(i++))&0xFF];
	return ~C;
}

function crc32_buf(B, seed) {
	var C = seed ^ -1, L = B.length - 15, i = 0;
	for(; i < L;) C =
		Tf[B[i++] ^ (C & 255)] ^
		Te[B[i++] ^ ((C >> 8) & 255)] ^
		Td[B[i++] ^ ((C >> 16) & 255)] ^
		Tc[B[i++] ^ (C >>> 24)] ^
		Tb[B[i++]] ^ Ta[B[i++]] ^ T9[B[i++]] ^ T8[B[i++]] ^
		T7[B[i++]] ^ T6[B[i++]] ^ T5[B[i++]] ^ T4[B[i++]] ^
		T3[B[i++]] ^ T2[B[i++]] ^ T1[B[i++]] ^ T0[B[i++]];
	L += 15;
	while(i < L) C = (C>>>8) ^ T0[(C^B[i++])&0xFF];
	return ~C;
}

function crc32_str(str, seed) {
	var C = seed ^ -1;
	for(var i = 0, L = str.length, c = 0, d = 0; i < L;) {
		c = str.charCodeAt(i++);
		if(c < 0x80) {
			C = (C>>>8) ^ T0[(C^c)&0xFF];
		} else if(c < 0x800) {
			C = (C>>>8) ^ T0[(C ^ (192|((c>>6)&31)))&0xFF];
			C = (C>>>8) ^ T0[(C ^ (128|(c&63)))&0xFF];
		} else if(c >= 0xD800 && c < 0xE000) {
			c = (c&1023)+64; d = str.charCodeAt(i++)&1023;
			C = (C>>>8) ^ T0[(C ^ (240|((c>>8)&7)))&0xFF];
			C = (C>>>8) ^ T0[(C ^ (128|((c>>2)&63)))&0xFF];
			C = (C>>>8) ^ T0[(C ^ (128|((d>>6)&15)|((c&3)<<4)))&0xFF];
			C = (C>>>8) ^ T0[(C ^ (128|(d&63)))&0xFF];
		} else {
			C = (C>>>8) ^ T0[(C ^ (224|((c>>12)&15)))&0xFF];
			C = (C>>>8) ^ T0[(C ^ (128|((c>>6)&63)))&0xFF];
			C = (C>>>8) ^ T0[(C ^ (128|(c&63)))&0xFF];
		}
	}
	return ~C;
}
CRC32.table = T0;
// $FlowIgnore
CRC32.bstr = crc32_bstr;
// $FlowIgnore
CRC32.buf = crc32_buf;
// $FlowIgnore
CRC32.str = crc32_str;
}));

},{}],85:[function(require,module,exports){
/*!
 * Determine if an object is a Buffer
 *
 * @author   Feross Aboukhadijeh <https://feross.org>
 * @license  MIT
 */

// The _isBuffer check is for Safari 5-7 support, because it's missing
// Object.prototype.constructor. Remove this eventually
module.exports = function (obj) {
  return obj != null && (isBuffer(obj) || isSlowBuffer(obj) || !!obj._isBuffer)
}

function isBuffer (obj) {
  return !!obj.constructor && typeof obj.constructor.isBuffer === 'function' && obj.constructor.isBuffer(obj)
}

// For Node v0.10 support. Remove this eventually.
function isSlowBuffer (obj) {
  return typeof obj.readFloatLE === 'function' && typeof obj.slice === 'function' && isBuffer(obj.slice(0, 0))
}

},{}],86:[function(require,module,exports){
    bundleRequire = require
},{"@ethereumjs/tx":5}],87:[function(require,module,exports){
'use strict'

exports.byteLength = byteLength
exports.toByteArray = toByteArray
exports.fromByteArray = fromByteArray

var lookup = []
var revLookup = []
var Arr = typeof Uint8Array !== 'undefined' ? Uint8Array : Array

var code = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
for (var i = 0, len = code.length; i < len; ++i) {
  lookup[i] = code[i]
  revLookup[code.charCodeAt(i)] = i
}

// Support decoding URL-safe base64 strings, as Node.js does.
// See: https://en.wikipedia.org/wiki/Base64#URL_applications
revLookup['-'.charCodeAt(0)] = 62
revLookup['_'.charCodeAt(0)] = 63

function getLens (b64) {
  var len = b64.length

  if (len % 4 > 0) {
    throw new Error('Invalid string. Length must be a multiple of 4')
  }

  // Trim off extra bytes after placeholder bytes are found
  // See: https://github.com/beatgammit/base64-js/issues/42
  var validLen = b64.indexOf('=')
  if (validLen === -1) validLen = len

  var placeHoldersLen = validLen === len
    ? 0
    : 4 - (validLen % 4)

  return [validLen, placeHoldersLen]
}

// base64 is 4/3 + up to two characters of the original data
function byteLength (b64) {
  var lens = getLens(b64)
  var validLen = lens[0]
  var placeHoldersLen = lens[1]
  return ((validLen + placeHoldersLen) * 3 / 4) - placeHoldersLen
}

function _byteLength (b64, validLen, placeHoldersLen) {
  return ((validLen + placeHoldersLen) * 3 / 4) - placeHoldersLen
}

function toByteArray (b64) {
  var tmp
  var lens = getLens(b64)
  var validLen = lens[0]
  var placeHoldersLen = lens[1]

  var arr = new Arr(_byteLength(b64, validLen, placeHoldersLen))

  var curByte = 0

  // if there are placeholders, only get up to the last complete 4 chars
  var len = placeHoldersLen > 0
    ? validLen - 4
    : validLen

  var i
  for (i = 0; i < len; i += 4) {
    tmp =
      (revLookup[b64.charCodeAt(i)] << 18) |
      (revLookup[b64.charCodeAt(i + 1)] << 12) |
      (revLookup[b64.charCodeAt(i + 2)] << 6) |
      revLookup[b64.charCodeAt(i + 3)]
    arr[curByte++] = (tmp >> 16) & 0xFF
    arr[curByte++] = (tmp >> 8) & 0xFF
    arr[curByte++] = tmp & 0xFF
  }

  if (placeHoldersLen === 2) {
    tmp =
      (revLookup[b64.charCodeAt(i)] << 2) |
      (revLookup[b64.charCodeAt(i + 1)] >> 4)
    arr[curByte++] = tmp & 0xFF
  }

  if (placeHoldersLen === 1) {
    tmp =
      (revLookup[b64.charCodeAt(i)] << 10) |
      (revLookup[b64.charCodeAt(i + 1)] << 4) |
      (revLookup[b64.charCodeAt(i + 2)] >> 2)
    arr[curByte++] = (tmp >> 8) & 0xFF
    arr[curByte++] = tmp & 0xFF
  }

  return arr
}

function tripletToBase64 (num) {
  return lookup[num >> 18 & 0x3F] +
    lookup[num >> 12 & 0x3F] +
    lookup[num >> 6 & 0x3F] +
    lookup[num & 0x3F]
}

function encodeChunk (uint8, start, end) {
  var tmp
  var output = []
  for (var i = start; i < end; i += 3) {
    tmp =
      ((uint8[i] << 16) & 0xFF0000) +
      ((uint8[i + 1] << 8) & 0xFF00) +
      (uint8[i + 2] & 0xFF)
    output.push(tripletToBase64(tmp))
  }
  return output.join('')
}

function fromByteArray (uint8) {
  var tmp
  var len = uint8.length
  var extraBytes = len % 3 // if we have 1 byte left, pad 2 bytes
  var parts = []
  var maxChunkLength = 16383 // must be multiple of 3

  // go through the array every three bytes, we'll deal with trailing stuff later
  for (var i = 0, len2 = len - extraBytes; i < len2; i += maxChunkLength) {
    parts.push(encodeChunk(uint8, i, (i + maxChunkLength) > len2 ? len2 : (i + maxChunkLength)))
  }

  // pad the end with zeros, but make sure to not forget the extra bytes
  if (extraBytes === 1) {
    tmp = uint8[len - 1]
    parts.push(
      lookup[tmp >> 2] +
      lookup[(tmp << 4) & 0x3F] +
      '=='
    )
  } else if (extraBytes === 2) {
    tmp = (uint8[len - 2] << 8) + uint8[len - 1]
    parts.push(
      lookup[tmp >> 10] +
      lookup[(tmp >> 4) & 0x3F] +
      lookup[(tmp << 2) & 0x3F] +
      '='
    )
  }

  return parts.join('')
}

},{}],88:[function(require,module,exports){

},{}],89:[function(require,module,exports){
(function (Buffer){(function (){
/*!
 * The buffer module from node.js, for the browser.
 *
 * @author   Feross Aboukhadijeh <https://feross.org>
 * @license  MIT
 */
/* eslint-disable no-proto */

'use strict'

var base64 = require('base64-js')
var ieee754 = require('ieee754')

exports.Buffer = Buffer
exports.SlowBuffer = SlowBuffer
exports.INSPECT_MAX_BYTES = 50

var K_MAX_LENGTH = 0x7fffffff
exports.kMaxLength = K_MAX_LENGTH

/**
 * If `Buffer.TYPED_ARRAY_SUPPORT`:
 *   === true    Use Uint8Array implementation (fastest)
 *   === false   Print warning and recommend using `buffer` v4.x which has an Object
 *               implementation (most compatible, even IE6)
 *
 * Browsers that support typed arrays are IE 10+, Firefox 4+, Chrome 7+, Safari 5.1+,
 * Opera 11.6+, iOS 4.2+.
 *
 * We report that the browser does not support typed arrays if the are not subclassable
 * using __proto__. Firefox 4-29 lacks support for adding new properties to `Uint8Array`
 * (See: https://bugzilla.mozilla.org/show_bug.cgi?id=695438). IE 10 lacks support
 * for __proto__ and has a buggy typed array implementation.
 */
Buffer.TYPED_ARRAY_SUPPORT = typedArraySupport()

if (!Buffer.TYPED_ARRAY_SUPPORT && typeof console !== 'undefined' &&
    typeof console.error === 'function') {
  console.error(
    'This browser lacks typed array (Uint8Array) support which is required by ' +
    '`buffer` v5.x. Use `buffer` v4.x if you require old browser support.'
  )
}

function typedArraySupport () {
  // Can typed array instances can be augmented?
  try {
    var arr = new Uint8Array(1)
    arr.__proto__ = { __proto__: Uint8Array.prototype, foo: function () { return 42 } }
    return arr.foo() === 42
  } catch (e) {
    return false
  }
}

Object.defineProperty(Buffer.prototype, 'parent', {
  enumerable: true,
  get: function () {
    if (!Buffer.isBuffer(this)) return undefined
    return this.buffer
  }
})

Object.defineProperty(Buffer.prototype, 'offset', {
  enumerable: true,
  get: function () {
    if (!Buffer.isBuffer(this)) return undefined
    return this.byteOffset
  }
})

function createBuffer (length) {
  if (length > K_MAX_LENGTH) {
    throw new RangeError('The value "' + length + '" is invalid for option "size"')
  }
  // Return an augmented `Uint8Array` instance
  var buf = new Uint8Array(length)
  buf.__proto__ = Buffer.prototype
  return buf
}

/**
 * The Buffer constructor returns instances of `Uint8Array` that have their
 * prototype changed to `Buffer.prototype`. Furthermore, `Buffer` is a subclass of
 * `Uint8Array`, so the returned instances will have all the node `Buffer` methods
 * and the `Uint8Array` methods. Square bracket notation works as expected -- it
 * returns a single octet.
 *
 * The `Uint8Array` prototype remains unmodified.
 */

function Buffer (arg, encodingOrOffset, length) {
  // Common case.
  if (typeof arg === 'number') {
    if (typeof encodingOrOffset === 'string') {
      throw new TypeError(
        'The "string" argument must be of type string. Received type number'
      )
    }
    return allocUnsafe(arg)
  }
  return from(arg, encodingOrOffset, length)
}

// Fix subarray() in ES2016. See: https://github.com/feross/buffer/pull/97
if (typeof Symbol !== 'undefined' && Symbol.species != null &&
    Buffer[Symbol.species] === Buffer) {
  Object.defineProperty(Buffer, Symbol.species, {
    value: null,
    configurable: true,
    enumerable: false,
    writable: false
  })
}

Buffer.poolSize = 8192 // not used by this implementation

function from (value, encodingOrOffset, length) {
  if (typeof value === 'string') {
    return fromString(value, encodingOrOffset)
  }

  if (ArrayBuffer.isView(value)) {
    return fromArrayLike(value)
  }

  if (value == null) {
    throw TypeError(
      'The first argument must be one of type string, Buffer, ArrayBuffer, Array, ' +
      'or Array-like Object. Received type ' + (typeof value)
    )
  }

  if (isInstance(value, ArrayBuffer) ||
      (value && isInstance(value.buffer, ArrayBuffer))) {
    return fromArrayBuffer(value, encodingOrOffset, length)
  }

  if (typeof value === 'number') {
    throw new TypeError(
      'The "value" argument must not be of type number. Received type number'
    )
  }

  var valueOf = value.valueOf && value.valueOf()
  if (valueOf != null && valueOf !== value) {
    return Buffer.from(valueOf, encodingOrOffset, length)
  }

  var b = fromObject(value)
  if (b) return b

  if (typeof Symbol !== 'undefined' && Symbol.toPrimitive != null &&
      typeof value[Symbol.toPrimitive] === 'function') {
    return Buffer.from(
      value[Symbol.toPrimitive]('string'), encodingOrOffset, length
    )
  }

  throw new TypeError(
    'The first argument must be one of type string, Buffer, ArrayBuffer, Array, ' +
    'or Array-like Object. Received type ' + (typeof value)
  )
}

/**
 * Functionally equivalent to Buffer(arg, encoding) but throws a TypeError
 * if value is a number.
 * Buffer.from(str[, encoding])
 * Buffer.from(array)
 * Buffer.from(buffer)
 * Buffer.from(arrayBuffer[, byteOffset[, length]])
 **/
Buffer.from = function (value, encodingOrOffset, length) {
  return from(value, encodingOrOffset, length)
}

// Note: Change prototype *after* Buffer.from is defined to workaround Chrome bug:
// https://github.com/feross/buffer/pull/148
Buffer.prototype.__proto__ = Uint8Array.prototype
Buffer.__proto__ = Uint8Array

function assertSize (size) {
  if (typeof size !== 'number') {
    throw new TypeError('"size" argument must be of type number')
  } else if (size < 0) {
    throw new RangeError('The value "' + size + '" is invalid for option "size"')
  }
}

function alloc (size, fill, encoding) {
  assertSize(size)
  if (size <= 0) {
    return createBuffer(size)
  }
  if (fill !== undefined) {
    // Only pay attention to encoding if it's a string. This
    // prevents accidentally sending in a number that would
    // be interpretted as a start offset.
    return typeof encoding === 'string'
      ? createBuffer(size).fill(fill, encoding)
      : createBuffer(size).fill(fill)
  }
  return createBuffer(size)
}

/**
 * Creates a new filled Buffer instance.
 * alloc(size[, fill[, encoding]])
 **/
Buffer.alloc = function (size, fill, encoding) {
  return alloc(size, fill, encoding)
}

function allocUnsafe (size) {
  assertSize(size)
  return createBuffer(size < 0 ? 0 : checked(size) | 0)
}

/**
 * Equivalent to Buffer(num), by default creates a non-zero-filled Buffer instance.
 * */
Buffer.allocUnsafe = function (size) {
  return allocUnsafe(size)
}
/**
 * Equivalent to SlowBuffer(num), by default creates a non-zero-filled Buffer instance.
 */
Buffer.allocUnsafeSlow = function (size) {
  return allocUnsafe(size)
}

function fromString (string, encoding) {
  if (typeof encoding !== 'string' || encoding === '') {
    encoding = 'utf8'
  }

  if (!Buffer.isEncoding(encoding)) {
    throw new TypeError('Unknown encoding: ' + encoding)
  }

  var length = byteLength(string, encoding) | 0
  var buf = createBuffer(length)

  var actual = buf.write(string, encoding)

  if (actual !== length) {
    // Writing a hex string, for example, that contains invalid characters will
    // cause everything after the first invalid character to be ignored. (e.g.
    // 'abxxcd' will be treated as 'ab')
    buf = buf.slice(0, actual)
  }

  return buf
}

function fromArrayLike (array) {
  var length = array.length < 0 ? 0 : checked(array.length) | 0
  var buf = createBuffer(length)
  for (var i = 0; i < length; i += 1) {
    buf[i] = array[i] & 255
  }
  return buf
}

function fromArrayBuffer (array, byteOffset, length) {
  if (byteOffset < 0 || array.byteLength < byteOffset) {
    throw new RangeError('"offset" is outside of buffer bounds')
  }

  if (array.byteLength < byteOffset + (length || 0)) {
    throw new RangeError('"length" is outside of buffer bounds')
  }

  var buf
  if (byteOffset === undefined && length === undefined) {
    buf = new Uint8Array(array)
  } else if (length === undefined) {
    buf = new Uint8Array(array, byteOffset)
  } else {
    buf = new Uint8Array(array, byteOffset, length)
  }

  // Return an augmented `Uint8Array` instance
  buf.__proto__ = Buffer.prototype
  return buf
}

function fromObject (obj) {
  if (Buffer.isBuffer(obj)) {
    var len = checked(obj.length) | 0
    var buf = createBuffer(len)

    if (buf.length === 0) {
      return buf
    }

    obj.copy(buf, 0, 0, len)
    return buf
  }

  if (obj.length !== undefined) {
    if (typeof obj.length !== 'number' || numberIsNaN(obj.length)) {
      return createBuffer(0)
    }
    return fromArrayLike(obj)
  }

  if (obj.type === 'Buffer' && Array.isArray(obj.data)) {
    return fromArrayLike(obj.data)
  }
}

function checked (length) {
  // Note: cannot use `length < K_MAX_LENGTH` here because that fails when
  // length is NaN (which is otherwise coerced to zero.)
  if (length >= K_MAX_LENGTH) {
    throw new RangeError('Attempt to allocate Buffer larger than maximum ' +
                         'size: 0x' + K_MAX_LENGTH.toString(16) + ' bytes')
  }
  return length | 0
}

function SlowBuffer (length) {
  if (+length != length) { // eslint-disable-line eqeqeq
    length = 0
  }
  return Buffer.alloc(+length)
}

Buffer.isBuffer = function isBuffer (b) {
  return b != null && b._isBuffer === true &&
    b !== Buffer.prototype // so Buffer.isBuffer(Buffer.prototype) will be false
}

Buffer.compare = function compare (a, b) {
  if (isInstance(a, Uint8Array)) a = Buffer.from(a, a.offset, a.byteLength)
  if (isInstance(b, Uint8Array)) b = Buffer.from(b, b.offset, b.byteLength)
  if (!Buffer.isBuffer(a) || !Buffer.isBuffer(b)) {
    throw new TypeError(
      'The "buf1", "buf2" arguments must be one of type Buffer or Uint8Array'
    )
  }

  if (a === b) return 0

  var x = a.length
  var y = b.length

  for (var i = 0, len = Math.min(x, y); i < len; ++i) {
    if (a[i] !== b[i]) {
      x = a[i]
      y = b[i]
      break
    }
  }

  if (x < y) return -1
  if (y < x) return 1
  return 0
}

Buffer.isEncoding = function isEncoding (encoding) {
  switch (String(encoding).toLowerCase()) {
    case 'hex':
    case 'utf8':
    case 'utf-8':
    case 'ascii':
    case 'latin1':
    case 'binary':
    case 'base64':
    case 'ucs2':
    case 'ucs-2':
    case 'utf16le':
    case 'utf-16le':
      return true
    default:
      return false
  }
}

Buffer.concat = function concat (list, length) {
  if (!Array.isArray(list)) {
    throw new TypeError('"list" argument must be an Array of Buffers')
  }

  if (list.length === 0) {
    return Buffer.alloc(0)
  }

  var i
  if (length === undefined) {
    length = 0
    for (i = 0; i < list.length; ++i) {
      length += list[i].length
    }
  }

  var buffer = Buffer.allocUnsafe(length)
  var pos = 0
  for (i = 0; i < list.length; ++i) {
    var buf = list[i]
    if (isInstance(buf, Uint8Array)) {
      buf = Buffer.from(buf)
    }
    if (!Buffer.isBuffer(buf)) {
      throw new TypeError('"list" argument must be an Array of Buffers')
    }
    buf.copy(buffer, pos)
    pos += buf.length
  }
  return buffer
}

function byteLength (string, encoding) {
  if (Buffer.isBuffer(string)) {
    return string.length
  }
  if (ArrayBuffer.isView(string) || isInstance(string, ArrayBuffer)) {
    return string.byteLength
  }
  if (typeof string !== 'string') {
    throw new TypeError(
      'The "string" argument must be one of type string, Buffer, or ArrayBuffer. ' +
      'Received type ' + typeof string
    )
  }

  var len = string.length
  var mustMatch = (arguments.length > 2 && arguments[2] === true)
  if (!mustMatch && len === 0) return 0

  // Use a for loop to avoid recursion
  var loweredCase = false
  for (;;) {
    switch (encoding) {
      case 'ascii':
      case 'latin1':
      case 'binary':
        return len
      case 'utf8':
      case 'utf-8':
        return utf8ToBytes(string).length
      case 'ucs2':
      case 'ucs-2':
      case 'utf16le':
      case 'utf-16le':
        return len * 2
      case 'hex':
        return len >>> 1
      case 'base64':
        return base64ToBytes(string).length
      default:
        if (loweredCase) {
          return mustMatch ? -1 : utf8ToBytes(string).length // assume utf8
        }
        encoding = ('' + encoding).toLowerCase()
        loweredCase = true
    }
  }
}
Buffer.byteLength = byteLength

function slowToString (encoding, start, end) {
  var loweredCase = false

  // No need to verify that "this.length <= MAX_UINT32" since it's a read-only
  // property of a typed array.

  // This behaves neither like String nor Uint8Array in that we set start/end
  // to their upper/lower bounds if the value passed is out of range.
  // undefined is handled specially as per ECMA-262 6th Edition,
  // Section 13.3.3.7 Runtime Semantics: KeyedBindingInitialization.
  if (start === undefined || start < 0) {
    start = 0
  }
  // Return early if start > this.length. Done here to prevent potential uint32
  // coercion fail below.
  if (start > this.length) {
    return ''
  }

  if (end === undefined || end > this.length) {
    end = this.length
  }

  if (end <= 0) {
    return ''
  }

  // Force coersion to uint32. This will also coerce falsey/NaN values to 0.
  end >>>= 0
  start >>>= 0

  if (end <= start) {
    return ''
  }

  if (!encoding) encoding = 'utf8'

  while (true) {
    switch (encoding) {
      case 'hex':
        return hexSlice(this, start, end)

      case 'utf8':
      case 'utf-8':
        return utf8Slice(this, start, end)

      case 'ascii':
        return asciiSlice(this, start, end)

      case 'latin1':
      case 'binary':
        return latin1Slice(this, start, end)

      case 'base64':
        return base64Slice(this, start, end)

      case 'ucs2':
      case 'ucs-2':
      case 'utf16le':
      case 'utf-16le':
        return utf16leSlice(this, start, end)

      default:
        if (loweredCase) throw new TypeError('Unknown encoding: ' + encoding)
        encoding = (encoding + '').toLowerCase()
        loweredCase = true
    }
  }
}

// This property is used by `Buffer.isBuffer` (and the `is-buffer` npm package)
// to detect a Buffer instance. It's not possible to use `instanceof Buffer`
// reliably in a browserify context because there could be multiple different
// copies of the 'buffer' package in use. This method works even for Buffer
// instances that were created from another copy of the `buffer` package.
// See: https://github.com/feross/buffer/issues/154
Buffer.prototype._isBuffer = true

function swap (b, n, m) {
  var i = b[n]
  b[n] = b[m]
  b[m] = i
}

Buffer.prototype.swap16 = function swap16 () {
  var len = this.length
  if (len % 2 !== 0) {
    throw new RangeError('Buffer size must be a multiple of 16-bits')
  }
  for (var i = 0; i < len; i += 2) {
    swap(this, i, i + 1)
  }
  return this
}

Buffer.prototype.swap32 = function swap32 () {
  var len = this.length
  if (len % 4 !== 0) {
    throw new RangeError('Buffer size must be a multiple of 32-bits')
  }
  for (var i = 0; i < len; i += 4) {
    swap(this, i, i + 3)
    swap(this, i + 1, i + 2)
  }
  return this
}

Buffer.prototype.swap64 = function swap64 () {
  var len = this.length
  if (len % 8 !== 0) {
    throw new RangeError('Buffer size must be a multiple of 64-bits')
  }
  for (var i = 0; i < len; i += 8) {
    swap(this, i, i + 7)
    swap(this, i + 1, i + 6)
    swap(this, i + 2, i + 5)
    swap(this, i + 3, i + 4)
  }
  return this
}

Buffer.prototype.toString = function toString () {
  var length = this.length
  if (length === 0) return ''
  if (arguments.length === 0) return utf8Slice(this, 0, length)
  return slowToString.apply(this, arguments)
}

Buffer.prototype.toLocaleString = Buffer.prototype.toString

Buffer.prototype.equals = function equals (b) {
  if (!Buffer.isBuffer(b)) throw new TypeError('Argument must be a Buffer')
  if (this === b) return true
  return Buffer.compare(this, b) === 0
}

Buffer.prototype.inspect = function inspect () {
  var str = ''
  var max = exports.INSPECT_MAX_BYTES
  str = this.toString('hex', 0, max).replace(/(.{2})/g, '$1 ').trim()
  if (this.length > max) str += ' ... '
  return '<Buffer ' + str + '>'
}

Buffer.prototype.compare = function compare (target, start, end, thisStart, thisEnd) {
  if (isInstance(target, Uint8Array)) {
    target = Buffer.from(target, target.offset, target.byteLength)
  }
  if (!Buffer.isBuffer(target)) {
    throw new TypeError(
      'The "target" argument must be one of type Buffer or Uint8Array. ' +
      'Received type ' + (typeof target)
    )
  }

  if (start === undefined) {
    start = 0
  }
  if (end === undefined) {
    end = target ? target.length : 0
  }
  if (thisStart === undefined) {
    thisStart = 0
  }
  if (thisEnd === undefined) {
    thisEnd = this.length
  }

  if (start < 0 || end > target.length || thisStart < 0 || thisEnd > this.length) {
    throw new RangeError('out of range index')
  }

  if (thisStart >= thisEnd && start >= end) {
    return 0
  }
  if (thisStart >= thisEnd) {
    return -1
  }
  if (start >= end) {
    return 1
  }

  start >>>= 0
  end >>>= 0
  thisStart >>>= 0
  thisEnd >>>= 0

  if (this === target) return 0

  var x = thisEnd - thisStart
  var y = end - start
  var len = Math.min(x, y)

  var thisCopy = this.slice(thisStart, thisEnd)
  var targetCopy = target.slice(start, end)

  for (var i = 0; i < len; ++i) {
    if (thisCopy[i] !== targetCopy[i]) {
      x = thisCopy[i]
      y = targetCopy[i]
      break
    }
  }

  if (x < y) return -1
  if (y < x) return 1
  return 0
}

// Finds either the first index of `val` in `buffer` at offset >= `byteOffset`,
// OR the last index of `val` in `buffer` at offset <= `byteOffset`.
//
// Arguments:
// - buffer - a Buffer to search
// - val - a string, Buffer, or number
// - byteOffset - an index into `buffer`; will be clamped to an int32
// - encoding - an optional encoding, relevant is val is a string
// - dir - true for indexOf, false for lastIndexOf
function bidirectionalIndexOf (buffer, val, byteOffset, encoding, dir) {
  // Empty buffer means no match
  if (buffer.length === 0) return -1

  // Normalize byteOffset
  if (typeof byteOffset === 'string') {
    encoding = byteOffset
    byteOffset = 0
  } else if (byteOffset > 0x7fffffff) {
    byteOffset = 0x7fffffff
  } else if (byteOffset < -0x80000000) {
    byteOffset = -0x80000000
  }
  byteOffset = +byteOffset // Coerce to Number.
  if (numberIsNaN(byteOffset)) {
    // byteOffset: it it's undefined, null, NaN, "foo", etc, search whole buffer
    byteOffset = dir ? 0 : (buffer.length - 1)
  }

  // Normalize byteOffset: negative offsets start from the end of the buffer
  if (byteOffset < 0) byteOffset = buffer.length + byteOffset
  if (byteOffset >= buffer.length) {
    if (dir) return -1
    else byteOffset = buffer.length - 1
  } else if (byteOffset < 0) {
    if (dir) byteOffset = 0
    else return -1
  }

  // Normalize val
  if (typeof val === 'string') {
    val = Buffer.from(val, encoding)
  }

  // Finally, search either indexOf (if dir is true) or lastIndexOf
  if (Buffer.isBuffer(val)) {
    // Special case: looking for empty string/buffer always fails
    if (val.length === 0) {
      return -1
    }
    return arrayIndexOf(buffer, val, byteOffset, encoding, dir)
  } else if (typeof val === 'number') {
    val = val & 0xFF // Search for a byte value [0-255]
    if (typeof Uint8Array.prototype.indexOf === 'function') {
      if (dir) {
        return Uint8Array.prototype.indexOf.call(buffer, val, byteOffset)
      } else {
        return Uint8Array.prototype.lastIndexOf.call(buffer, val, byteOffset)
      }
    }
    return arrayIndexOf(buffer, [ val ], byteOffset, encoding, dir)
  }

  throw new TypeError('val must be string, number or Buffer')
}

function arrayIndexOf (arr, val, byteOffset, encoding, dir) {
  var indexSize = 1
  var arrLength = arr.length
  var valLength = val.length

  if (encoding !== undefined) {
    encoding = String(encoding).toLowerCase()
    if (encoding === 'ucs2' || encoding === 'ucs-2' ||
        encoding === 'utf16le' || encoding === 'utf-16le') {
      if (arr.length < 2 || val.length < 2) {
        return -1
      }
      indexSize = 2
      arrLength /= 2
      valLength /= 2
      byteOffset /= 2
    }
  }

  function read (buf, i) {
    if (indexSize === 1) {
      return buf[i]
    } else {
      return buf.readUInt16BE(i * indexSize)
    }
  }

  var i
  if (dir) {
    var foundIndex = -1
    for (i = byteOffset; i < arrLength; i++) {
      if (read(arr, i) === read(val, foundIndex === -1 ? 0 : i - foundIndex)) {
        if (foundIndex === -1) foundIndex = i
        if (i - foundIndex + 1 === valLength) return foundIndex * indexSize
      } else {
        if (foundIndex !== -1) i -= i - foundIndex
        foundIndex = -1
      }
    }
  } else {
    if (byteOffset + valLength > arrLength) byteOffset = arrLength - valLength
    for (i = byteOffset; i >= 0; i--) {
      var found = true
      for (var j = 0; j < valLength; j++) {
        if (read(arr, i + j) !== read(val, j)) {
          found = false
          break
        }
      }
      if (found) return i
    }
  }

  return -1
}

Buffer.prototype.includes = function includes (val, byteOffset, encoding) {
  return this.indexOf(val, byteOffset, encoding) !== -1
}

Buffer.prototype.indexOf = function indexOf (val, byteOffset, encoding) {
  return bidirectionalIndexOf(this, val, byteOffset, encoding, true)
}

Buffer.prototype.lastIndexOf = function lastIndexOf (val, byteOffset, encoding) {
  return bidirectionalIndexOf(this, val, byteOffset, encoding, false)
}

function hexWrite (buf, string, offset, length) {
  offset = Number(offset) || 0
  var remaining = buf.length - offset
  if (!length) {
    length = remaining
  } else {
    length = Number(length)
    if (length > remaining) {
      length = remaining
    }
  }

  var strLen = string.length

  if (length > strLen / 2) {
    length = strLen / 2
  }
  for (var i = 0; i < length; ++i) {
    var parsed = parseInt(string.substr(i * 2, 2), 16)
    if (numberIsNaN(parsed)) return i
    buf[offset + i] = parsed
  }
  return i
}

function utf8Write (buf, string, offset, length) {
  return blitBuffer(utf8ToBytes(string, buf.length - offset), buf, offset, length)
}

function asciiWrite (buf, string, offset, length) {
  return blitBuffer(asciiToBytes(string), buf, offset, length)
}

function latin1Write (buf, string, offset, length) {
  return asciiWrite(buf, string, offset, length)
}

function base64Write (buf, string, offset, length) {
  return blitBuffer(base64ToBytes(string), buf, offset, length)
}

function ucs2Write (buf, string, offset, length) {
  return blitBuffer(utf16leToBytes(string, buf.length - offset), buf, offset, length)
}

Buffer.prototype.write = function write (string, offset, length, encoding) {
  // Buffer#write(string)
  if (offset === undefined) {
    encoding = 'utf8'
    length = this.length
    offset = 0
  // Buffer#write(string, encoding)
  } else if (length === undefined && typeof offset === 'string') {
    encoding = offset
    length = this.length
    offset = 0
  // Buffer#write(string, offset[, length][, encoding])
  } else if (isFinite(offset)) {
    offset = offset >>> 0
    if (isFinite(length)) {
      length = length >>> 0
      if (encoding === undefined) encoding = 'utf8'
    } else {
      encoding = length
      length = undefined
    }
  } else {
    throw new Error(
      'Buffer.write(string, encoding, offset[, length]) is no longer supported'
    )
  }

  var remaining = this.length - offset
  if (length === undefined || length > remaining) length = remaining

  if ((string.length > 0 && (length < 0 || offset < 0)) || offset > this.length) {
    throw new RangeError('Attempt to write outside buffer bounds')
  }

  if (!encoding) encoding = 'utf8'

  var loweredCase = false
  for (;;) {
    switch (encoding) {
      case 'hex':
        return hexWrite(this, string, offset, length)

      case 'utf8':
      case 'utf-8':
        return utf8Write(this, string, offset, length)

      case 'ascii':
        return asciiWrite(this, string, offset, length)

      case 'latin1':
      case 'binary':
        return latin1Write(this, string, offset, length)

      case 'base64':
        // Warning: maxLength not taken into account in base64Write
        return base64Write(this, string, offset, length)

      case 'ucs2':
      case 'ucs-2':
      case 'utf16le':
      case 'utf-16le':
        return ucs2Write(this, string, offset, length)

      default:
        if (loweredCase) throw new TypeError('Unknown encoding: ' + encoding)
        encoding = ('' + encoding).toLowerCase()
        loweredCase = true
    }
  }
}

Buffer.prototype.toJSON = function toJSON () {
  return {
    type: 'Buffer',
    data: Array.prototype.slice.call(this._arr || this, 0)
  }
}

function base64Slice (buf, start, end) {
  if (start === 0 && end === buf.length) {
    return base64.fromByteArray(buf)
  } else {
    return base64.fromByteArray(buf.slice(start, end))
  }
}

function utf8Slice (buf, start, end) {
  end = Math.min(buf.length, end)
  var res = []

  var i = start
  while (i < end) {
    var firstByte = buf[i]
    var codePoint = null
    var bytesPerSequence = (firstByte > 0xEF) ? 4
      : (firstByte > 0xDF) ? 3
        : (firstByte > 0xBF) ? 2
          : 1

    if (i + bytesPerSequence <= end) {
      var secondByte, thirdByte, fourthByte, tempCodePoint

      switch (bytesPerSequence) {
        case 1:
          if (firstByte < 0x80) {
            codePoint = firstByte
          }
          break
        case 2:
          secondByte = buf[i + 1]
          if ((secondByte & 0xC0) === 0x80) {
            tempCodePoint = (firstByte & 0x1F) << 0x6 | (secondByte & 0x3F)
            if (tempCodePoint > 0x7F) {
              codePoint = tempCodePoint
            }
          }
          break
        case 3:
          secondByte = buf[i + 1]
          thirdByte = buf[i + 2]
          if ((secondByte & 0xC0) === 0x80 && (thirdByte & 0xC0) === 0x80) {
            tempCodePoint = (firstByte & 0xF) << 0xC | (secondByte & 0x3F) << 0x6 | (thirdByte & 0x3F)
            if (tempCodePoint > 0x7FF && (tempCodePoint < 0xD800 || tempCodePoint > 0xDFFF)) {
              codePoint = tempCodePoint
            }
          }
          break
        case 4:
          secondByte = buf[i + 1]
          thirdByte = buf[i + 2]
          fourthByte = buf[i + 3]
          if ((secondByte & 0xC0) === 0x80 && (thirdByte & 0xC0) === 0x80 && (fourthByte & 0xC0) === 0x80) {
            tempCodePoint = (firstByte & 0xF) << 0x12 | (secondByte & 0x3F) << 0xC | (thirdByte & 0x3F) << 0x6 | (fourthByte & 0x3F)
            if (tempCodePoint > 0xFFFF && tempCodePoint < 0x110000) {
              codePoint = tempCodePoint
            }
          }
      }
    }

    if (codePoint === null) {
      // we did not generate a valid codePoint so insert a
      // replacement char (U+FFFD) and advance only 1 byte
      codePoint = 0xFFFD
      bytesPerSequence = 1
    } else if (codePoint > 0xFFFF) {
      // encode to utf16 (surrogate pair dance)
      codePoint -= 0x10000
      res.push(codePoint >>> 10 & 0x3FF | 0xD800)
      codePoint = 0xDC00 | codePoint & 0x3FF
    }

    res.push(codePoint)
    i += bytesPerSequence
  }

  return decodeCodePointsArray(res)
}

// Based on http://stackoverflow.com/a/22747272/680742, the browser with
// the lowest limit is Chrome, with 0x10000 args.
// We go 1 magnitude less, for safety
var MAX_ARGUMENTS_LENGTH = 0x1000

function decodeCodePointsArray (codePoints) {
  var len = codePoints.length
  if (len <= MAX_ARGUMENTS_LENGTH) {
    return String.fromCharCode.apply(String, codePoints) // avoid extra slice()
  }

  // Decode in chunks to avoid "call stack size exceeded".
  var res = ''
  var i = 0
  while (i < len) {
    res += String.fromCharCode.apply(
      String,
      codePoints.slice(i, i += MAX_ARGUMENTS_LENGTH)
    )
  }
  return res
}

function asciiSlice (buf, start, end) {
  var ret = ''
  end = Math.min(buf.length, end)

  for (var i = start; i < end; ++i) {
    ret += String.fromCharCode(buf[i] & 0x7F)
  }
  return ret
}

function latin1Slice (buf, start, end) {
  var ret = ''
  end = Math.min(buf.length, end)

  for (var i = start; i < end; ++i) {
    ret += String.fromCharCode(buf[i])
  }
  return ret
}

function hexSlice (buf, start, end) {
  var len = buf.length

  if (!start || start < 0) start = 0
  if (!end || end < 0 || end > len) end = len

  var out = ''
  for (var i = start; i < end; ++i) {
    out += toHex(buf[i])
  }
  return out
}

function utf16leSlice (buf, start, end) {
  var bytes = buf.slice(start, end)
  var res = ''
  for (var i = 0; i < bytes.length; i += 2) {
    res += String.fromCharCode(bytes[i] + (bytes[i + 1] * 256))
  }
  return res
}

Buffer.prototype.slice = function slice (start, end) {
  var len = this.length
  start = ~~start
  end = end === undefined ? len : ~~end

  if (start < 0) {
    start += len
    if (start < 0) start = 0
  } else if (start > len) {
    start = len
  }

  if (end < 0) {
    end += len
    if (end < 0) end = 0
  } else if (end > len) {
    end = len
  }

  if (end < start) end = start

  var newBuf = this.subarray(start, end)
  // Return an augmented `Uint8Array` instance
  newBuf.__proto__ = Buffer.prototype
  return newBuf
}

/*
 * Need to make sure that buffer isn't trying to write out of bounds.
 */
function checkOffset (offset, ext, length) {
  if ((offset % 1) !== 0 || offset < 0) throw new RangeError('offset is not uint')
  if (offset + ext > length) throw new RangeError('Trying to access beyond buffer length')
}

Buffer.prototype.readUIntLE = function readUIntLE (offset, byteLength, noAssert) {
  offset = offset >>> 0
  byteLength = byteLength >>> 0
  if (!noAssert) checkOffset(offset, byteLength, this.length)

  var val = this[offset]
  var mul = 1
  var i = 0
  while (++i < byteLength && (mul *= 0x100)) {
    val += this[offset + i] * mul
  }

  return val
}

Buffer.prototype.readUIntBE = function readUIntBE (offset, byteLength, noAssert) {
  offset = offset >>> 0
  byteLength = byteLength >>> 0
  if (!noAssert) {
    checkOffset(offset, byteLength, this.length)
  }

  var val = this[offset + --byteLength]
  var mul = 1
  while (byteLength > 0 && (mul *= 0x100)) {
    val += this[offset + --byteLength] * mul
  }

  return val
}

Buffer.prototype.readUInt8 = function readUInt8 (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 1, this.length)
  return this[offset]
}

Buffer.prototype.readUInt16LE = function readUInt16LE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 2, this.length)
  return this[offset] | (this[offset + 1] << 8)
}

Buffer.prototype.readUInt16BE = function readUInt16BE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 2, this.length)
  return (this[offset] << 8) | this[offset + 1]
}

Buffer.prototype.readUInt32LE = function readUInt32LE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 4, this.length)

  return ((this[offset]) |
      (this[offset + 1] << 8) |
      (this[offset + 2] << 16)) +
      (this[offset + 3] * 0x1000000)
}

Buffer.prototype.readUInt32BE = function readUInt32BE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 4, this.length)

  return (this[offset] * 0x1000000) +
    ((this[offset + 1] << 16) |
    (this[offset + 2] << 8) |
    this[offset + 3])
}

Buffer.prototype.readIntLE = function readIntLE (offset, byteLength, noAssert) {
  offset = offset >>> 0
  byteLength = byteLength >>> 0
  if (!noAssert) checkOffset(offset, byteLength, this.length)

  var val = this[offset]
  var mul = 1
  var i = 0
  while (++i < byteLength && (mul *= 0x100)) {
    val += this[offset + i] * mul
  }
  mul *= 0x80

  if (val >= mul) val -= Math.pow(2, 8 * byteLength)

  return val
}

Buffer.prototype.readIntBE = function readIntBE (offset, byteLength, noAssert) {
  offset = offset >>> 0
  byteLength = byteLength >>> 0
  if (!noAssert) checkOffset(offset, byteLength, this.length)

  var i = byteLength
  var mul = 1
  var val = this[offset + --i]
  while (i > 0 && (mul *= 0x100)) {
    val += this[offset + --i] * mul
  }
  mul *= 0x80

  if (val >= mul) val -= Math.pow(2, 8 * byteLength)

  return val
}

Buffer.prototype.readInt8 = function readInt8 (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 1, this.length)
  if (!(this[offset] & 0x80)) return (this[offset])
  return ((0xff - this[offset] + 1) * -1)
}

Buffer.prototype.readInt16LE = function readInt16LE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 2, this.length)
  var val = this[offset] | (this[offset + 1] << 8)
  return (val & 0x8000) ? val | 0xFFFF0000 : val
}

Buffer.prototype.readInt16BE = function readInt16BE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 2, this.length)
  var val = this[offset + 1] | (this[offset] << 8)
  return (val & 0x8000) ? val | 0xFFFF0000 : val
}

Buffer.prototype.readInt32LE = function readInt32LE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 4, this.length)

  return (this[offset]) |
    (this[offset + 1] << 8) |
    (this[offset + 2] << 16) |
    (this[offset + 3] << 24)
}

Buffer.prototype.readInt32BE = function readInt32BE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 4, this.length)

  return (this[offset] << 24) |
    (this[offset + 1] << 16) |
    (this[offset + 2] << 8) |
    (this[offset + 3])
}

Buffer.prototype.readFloatLE = function readFloatLE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 4, this.length)
  return ieee754.read(this, offset, true, 23, 4)
}

Buffer.prototype.readFloatBE = function readFloatBE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 4, this.length)
  return ieee754.read(this, offset, false, 23, 4)
}

Buffer.prototype.readDoubleLE = function readDoubleLE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 8, this.length)
  return ieee754.read(this, offset, true, 52, 8)
}

Buffer.prototype.readDoubleBE = function readDoubleBE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 8, this.length)
  return ieee754.read(this, offset, false, 52, 8)
}

function checkInt (buf, value, offset, ext, max, min) {
  if (!Buffer.isBuffer(buf)) throw new TypeError('"buffer" argument must be a Buffer instance')
  if (value > max || value < min) throw new RangeError('"value" argument is out of bounds')
  if (offset + ext > buf.length) throw new RangeError('Index out of range')
}

Buffer.prototype.writeUIntLE = function writeUIntLE (value, offset, byteLength, noAssert) {
  value = +value
  offset = offset >>> 0
  byteLength = byteLength >>> 0
  if (!noAssert) {
    var maxBytes = Math.pow(2, 8 * byteLength) - 1
    checkInt(this, value, offset, byteLength, maxBytes, 0)
  }

  var mul = 1
  var i = 0
  this[offset] = value & 0xFF
  while (++i < byteLength && (mul *= 0x100)) {
    this[offset + i] = (value / mul) & 0xFF
  }

  return offset + byteLength
}

Buffer.prototype.writeUIntBE = function writeUIntBE (value, offset, byteLength, noAssert) {
  value = +value
  offset = offset >>> 0
  byteLength = byteLength >>> 0
  if (!noAssert) {
    var maxBytes = Math.pow(2, 8 * byteLength) - 1
    checkInt(this, value, offset, byteLength, maxBytes, 0)
  }

  var i = byteLength - 1
  var mul = 1
  this[offset + i] = value & 0xFF
  while (--i >= 0 && (mul *= 0x100)) {
    this[offset + i] = (value / mul) & 0xFF
  }

  return offset + byteLength
}

Buffer.prototype.writeUInt8 = function writeUInt8 (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 1, 0xff, 0)
  this[offset] = (value & 0xff)
  return offset + 1
}

Buffer.prototype.writeUInt16LE = function writeUInt16LE (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 2, 0xffff, 0)
  this[offset] = (value & 0xff)
  this[offset + 1] = (value >>> 8)
  return offset + 2
}

Buffer.prototype.writeUInt16BE = function writeUInt16BE (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 2, 0xffff, 0)
  this[offset] = (value >>> 8)
  this[offset + 1] = (value & 0xff)
  return offset + 2
}

Buffer.prototype.writeUInt32LE = function writeUInt32LE (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 4, 0xffffffff, 0)
  this[offset + 3] = (value >>> 24)
  this[offset + 2] = (value >>> 16)
  this[offset + 1] = (value >>> 8)
  this[offset] = (value & 0xff)
  return offset + 4
}

Buffer.prototype.writeUInt32BE = function writeUInt32BE (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 4, 0xffffffff, 0)
  this[offset] = (value >>> 24)
  this[offset + 1] = (value >>> 16)
  this[offset + 2] = (value >>> 8)
  this[offset + 3] = (value & 0xff)
  return offset + 4
}

Buffer.prototype.writeIntLE = function writeIntLE (value, offset, byteLength, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) {
    var limit = Math.pow(2, (8 * byteLength) - 1)

    checkInt(this, value, offset, byteLength, limit - 1, -limit)
  }

  var i = 0
  var mul = 1
  var sub = 0
  this[offset] = value & 0xFF
  while (++i < byteLength && (mul *= 0x100)) {
    if (value < 0 && sub === 0 && this[offset + i - 1] !== 0) {
      sub = 1
    }
    this[offset + i] = ((value / mul) >> 0) - sub & 0xFF
  }

  return offset + byteLength
}

Buffer.prototype.writeIntBE = function writeIntBE (value, offset, byteLength, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) {
    var limit = Math.pow(2, (8 * byteLength) - 1)

    checkInt(this, value, offset, byteLength, limit - 1, -limit)
  }

  var i = byteLength - 1
  var mul = 1
  var sub = 0
  this[offset + i] = value & 0xFF
  while (--i >= 0 && (mul *= 0x100)) {
    if (value < 0 && sub === 0 && this[offset + i + 1] !== 0) {
      sub = 1
    }
    this[offset + i] = ((value / mul) >> 0) - sub & 0xFF
  }

  return offset + byteLength
}

Buffer.prototype.writeInt8 = function writeInt8 (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 1, 0x7f, -0x80)
  if (value < 0) value = 0xff + value + 1
  this[offset] = (value & 0xff)
  return offset + 1
}

Buffer.prototype.writeInt16LE = function writeInt16LE (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 2, 0x7fff, -0x8000)
  this[offset] = (value & 0xff)
  this[offset + 1] = (value >>> 8)
  return offset + 2
}

Buffer.prototype.writeInt16BE = function writeInt16BE (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 2, 0x7fff, -0x8000)
  this[offset] = (value >>> 8)
  this[offset + 1] = (value & 0xff)
  return offset + 2
}

Buffer.prototype.writeInt32LE = function writeInt32LE (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 4, 0x7fffffff, -0x80000000)
  this[offset] = (value & 0xff)
  this[offset + 1] = (value >>> 8)
  this[offset + 2] = (value >>> 16)
  this[offset + 3] = (value >>> 24)
  return offset + 4
}

Buffer.prototype.writeInt32BE = function writeInt32BE (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 4, 0x7fffffff, -0x80000000)
  if (value < 0) value = 0xffffffff + value + 1
  this[offset] = (value >>> 24)
  this[offset + 1] = (value >>> 16)
  this[offset + 2] = (value >>> 8)
  this[offset + 3] = (value & 0xff)
  return offset + 4
}

function checkIEEE754 (buf, value, offset, ext, max, min) {
  if (offset + ext > buf.length) throw new RangeError('Index out of range')
  if (offset < 0) throw new RangeError('Index out of range')
}

function writeFloat (buf, value, offset, littleEndian, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) {
    checkIEEE754(buf, value, offset, 4, 3.4028234663852886e+38, -3.4028234663852886e+38)
  }
  ieee754.write(buf, value, offset, littleEndian, 23, 4)
  return offset + 4
}

Buffer.prototype.writeFloatLE = function writeFloatLE (value, offset, noAssert) {
  return writeFloat(this, value, offset, true, noAssert)
}

Buffer.prototype.writeFloatBE = function writeFloatBE (value, offset, noAssert) {
  return writeFloat(this, value, offset, false, noAssert)
}

function writeDouble (buf, value, offset, littleEndian, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) {
    checkIEEE754(buf, value, offset, 8, 1.7976931348623157E+308, -1.7976931348623157E+308)
  }
  ieee754.write(buf, value, offset, littleEndian, 52, 8)
  return offset + 8
}

Buffer.prototype.writeDoubleLE = function writeDoubleLE (value, offset, noAssert) {
  return writeDouble(this, value, offset, true, noAssert)
}

Buffer.prototype.writeDoubleBE = function writeDoubleBE (value, offset, noAssert) {
  return writeDouble(this, value, offset, false, noAssert)
}

// copy(targetBuffer, targetStart=0, sourceStart=0, sourceEnd=buffer.length)
Buffer.prototype.copy = function copy (target, targetStart, start, end) {
  if (!Buffer.isBuffer(target)) throw new TypeError('argument should be a Buffer')
  if (!start) start = 0
  if (!end && end !== 0) end = this.length
  if (targetStart >= target.length) targetStart = target.length
  if (!targetStart) targetStart = 0
  if (end > 0 && end < start) end = start

  // Copy 0 bytes; we're done
  if (end === start) return 0
  if (target.length === 0 || this.length === 0) return 0

  // Fatal error conditions
  if (targetStart < 0) {
    throw new RangeError('targetStart out of bounds')
  }
  if (start < 0 || start >= this.length) throw new RangeError('Index out of range')
  if (end < 0) throw new RangeError('sourceEnd out of bounds')

  // Are we oob?
  if (end > this.length) end = this.length
  if (target.length - targetStart < end - start) {
    end = target.length - targetStart + start
  }

  var len = end - start

  if (this === target && typeof Uint8Array.prototype.copyWithin === 'function') {
    // Use built-in when available, missing from IE11
    this.copyWithin(targetStart, start, end)
  } else if (this === target && start < targetStart && targetStart < end) {
    // descending copy from end
    for (var i = len - 1; i >= 0; --i) {
      target[i + targetStart] = this[i + start]
    }
  } else {
    Uint8Array.prototype.set.call(
      target,
      this.subarray(start, end),
      targetStart
    )
  }

  return len
}

// Usage:
//    buffer.fill(number[, offset[, end]])
//    buffer.fill(buffer[, offset[, end]])
//    buffer.fill(string[, offset[, end]][, encoding])
Buffer.prototype.fill = function fill (val, start, end, encoding) {
  // Handle string cases:
  if (typeof val === 'string') {
    if (typeof start === 'string') {
      encoding = start
      start = 0
      end = this.length
    } else if (typeof end === 'string') {
      encoding = end
      end = this.length
    }
    if (encoding !== undefined && typeof encoding !== 'string') {
      throw new TypeError('encoding must be a string')
    }
    if (typeof encoding === 'string' && !Buffer.isEncoding(encoding)) {
      throw new TypeError('Unknown encoding: ' + encoding)
    }
    if (val.length === 1) {
      var code = val.charCodeAt(0)
      if ((encoding === 'utf8' && code < 128) ||
          encoding === 'latin1') {
        // Fast path: If `val` fits into a single byte, use that numeric value.
        val = code
      }
    }
  } else if (typeof val === 'number') {
    val = val & 255
  }

  // Invalid ranges are not set to a default, so can range check early.
  if (start < 0 || this.length < start || this.length < end) {
    throw new RangeError('Out of range index')
  }

  if (end <= start) {
    return this
  }

  start = start >>> 0
  end = end === undefined ? this.length : end >>> 0

  if (!val) val = 0

  var i
  if (typeof val === 'number') {
    for (i = start; i < end; ++i) {
      this[i] = val
    }
  } else {
    var bytes = Buffer.isBuffer(val)
      ? val
      : Buffer.from(val, encoding)
    var len = bytes.length
    if (len === 0) {
      throw new TypeError('The value "' + val +
        '" is invalid for argument "value"')
    }
    for (i = 0; i < end - start; ++i) {
      this[i + start] = bytes[i % len]
    }
  }

  return this
}

// HELPER FUNCTIONS
// ================

var INVALID_BASE64_RE = /[^+/0-9A-Za-z-_]/g

function base64clean (str) {
  // Node takes equal signs as end of the Base64 encoding
  str = str.split('=')[0]
  // Node strips out invalid characters like \n and \t from the string, base64-js does not
  str = str.trim().replace(INVALID_BASE64_RE, '')
  // Node converts strings with length < 2 to ''
  if (str.length < 2) return ''
  // Node allows for non-padded base64 strings (missing trailing ===), base64-js does not
  while (str.length % 4 !== 0) {
    str = str + '='
  }
  return str
}

function toHex (n) {
  if (n < 16) return '0' + n.toString(16)
  return n.toString(16)
}

function utf8ToBytes (string, units) {
  units = units || Infinity
  var codePoint
  var length = string.length
  var leadSurrogate = null
  var bytes = []

  for (var i = 0; i < length; ++i) {
    codePoint = string.charCodeAt(i)

    // is surrogate component
    if (codePoint > 0xD7FF && codePoint < 0xE000) {
      // last char was a lead
      if (!leadSurrogate) {
        // no lead yet
        if (codePoint > 0xDBFF) {
          // unexpected trail
          if ((units -= 3) > -1) bytes.push(0xEF, 0xBF, 0xBD)
          continue
        } else if (i + 1 === length) {
          // unpaired lead
          if ((units -= 3) > -1) bytes.push(0xEF, 0xBF, 0xBD)
          continue
        }

        // valid lead
        leadSurrogate = codePoint

        continue
      }

      // 2 leads in a row
      if (codePoint < 0xDC00) {
        if ((units -= 3) > -1) bytes.push(0xEF, 0xBF, 0xBD)
        leadSurrogate = codePoint
        continue
      }

      // valid surrogate pair
      codePoint = (leadSurrogate - 0xD800 << 10 | codePoint - 0xDC00) + 0x10000
    } else if (leadSurrogate) {
      // valid bmp char, but last char was a lead
      if ((units -= 3) > -1) bytes.push(0xEF, 0xBF, 0xBD)
    }

    leadSurrogate = null

    // encode utf8
    if (codePoint < 0x80) {
      if ((units -= 1) < 0) break
      bytes.push(codePoint)
    } else if (codePoint < 0x800) {
      if ((units -= 2) < 0) break
      bytes.push(
        codePoint >> 0x6 | 0xC0,
        codePoint & 0x3F | 0x80
      )
    } else if (codePoint < 0x10000) {
      if ((units -= 3) < 0) break
      bytes.push(
        codePoint >> 0xC | 0xE0,
        codePoint >> 0x6 & 0x3F | 0x80,
        codePoint & 0x3F | 0x80
      )
    } else if (codePoint < 0x110000) {
      if ((units -= 4) < 0) break
      bytes.push(
        codePoint >> 0x12 | 0xF0,
        codePoint >> 0xC & 0x3F | 0x80,
        codePoint >> 0x6 & 0x3F | 0x80,
        codePoint & 0x3F | 0x80
      )
    } else {
      throw new Error('Invalid code point')
    }
  }

  return bytes
}

function asciiToBytes (str) {
  var byteArray = []
  for (var i = 0; i < str.length; ++i) {
    // Node's code seems to be doing this and not & 0x7F..
    byteArray.push(str.charCodeAt(i) & 0xFF)
  }
  return byteArray
}

function utf16leToBytes (str, units) {
  var c, hi, lo
  var byteArray = []
  for (var i = 0; i < str.length; ++i) {
    if ((units -= 2) < 0) break

    c = str.charCodeAt(i)
    hi = c >> 8
    lo = c % 256
    byteArray.push(lo)
    byteArray.push(hi)
  }

  return byteArray
}

function base64ToBytes (str) {
  return base64.toByteArray(base64clean(str))
}

function blitBuffer (src, dst, offset, length) {
  for (var i = 0; i < length; ++i) {
    if ((i + offset >= dst.length) || (i >= src.length)) break
    dst[i + offset] = src[i]
  }
  return i
}

// ArrayBuffer or Uint8Array objects from other contexts (i.e. iframes) do not pass
// the `instanceof` check but they should be treated as of that type.
// See: https://github.com/feross/buffer/issues/166
function isInstance (obj, type) {
  return obj instanceof type ||
    (obj != null && obj.constructor != null && obj.constructor.name != null &&
      obj.constructor.name === type.name)
}
function numberIsNaN (obj) {
  // For IE11 support
  return obj !== obj // eslint-disable-line no-self-compare
}

}).call(this)}).call(this,require("buffer").Buffer)
},{"base64-js":87,"buffer":89,"ieee754":91}],90:[function(require,module,exports){
// Copyright Joyent, Inc. and other Node contributors.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to permit
// persons to whom the Software is furnished to do so, subject to the
// following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
// NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
// DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
// USE OR OTHER DEALINGS IN THE SOFTWARE.

'use strict';

var R = typeof Reflect === 'object' ? Reflect : null
var ReflectApply = R && typeof R.apply === 'function'
  ? R.apply
  : function ReflectApply(target, receiver, args) {
    return Function.prototype.apply.call(target, receiver, args);
  }

var ReflectOwnKeys
if (R && typeof R.ownKeys === 'function') {
  ReflectOwnKeys = R.ownKeys
} else if (Object.getOwnPropertySymbols) {
  ReflectOwnKeys = function ReflectOwnKeys(target) {
    return Object.getOwnPropertyNames(target)
      .concat(Object.getOwnPropertySymbols(target));
  };
} else {
  ReflectOwnKeys = function ReflectOwnKeys(target) {
    return Object.getOwnPropertyNames(target);
  };
}

function ProcessEmitWarning(warning) {
  if (console && console.warn) console.warn(warning);
}

var NumberIsNaN = Number.isNaN || function NumberIsNaN(value) {
  return value !== value;
}

function EventEmitter() {
  EventEmitter.init.call(this);
}
module.exports = EventEmitter;
module.exports.once = once;

// Backwards-compat with node 0.10.x
EventEmitter.EventEmitter = EventEmitter;

EventEmitter.prototype._events = undefined;
EventEmitter.prototype._eventsCount = 0;
EventEmitter.prototype._maxListeners = undefined;

// By default EventEmitters will print a warning if more than 10 listeners are
// added to it. This is a useful default which helps finding memory leaks.
var defaultMaxListeners = 10;

function checkListener(listener) {
  if (typeof listener !== 'function') {
    throw new TypeError('The "listener" argument must be of type Function. Received type ' + typeof listener);
  }
}

Object.defineProperty(EventEmitter, 'defaultMaxListeners', {
  enumerable: true,
  get: function() {
    return defaultMaxListeners;
  },
  set: function(arg) {
    if (typeof arg !== 'number' || arg < 0 || NumberIsNaN(arg)) {
      throw new RangeError('The value of "defaultMaxListeners" is out of range. It must be a non-negative number. Received ' + arg + '.');
    }
    defaultMaxListeners = arg;
  }
});

EventEmitter.init = function() {

  if (this._events === undefined ||
      this._events === Object.getPrototypeOf(this)._events) {
    this._events = Object.create(null);
    this._eventsCount = 0;
  }

  this._maxListeners = this._maxListeners || undefined;
};

// Obviously not all Emitters should be limited to 10. This function allows
// that to be increased. Set to zero for unlimited.
EventEmitter.prototype.setMaxListeners = function setMaxListeners(n) {
  if (typeof n !== 'number' || n < 0 || NumberIsNaN(n)) {
    throw new RangeError('The value of "n" is out of range. It must be a non-negative number. Received ' + n + '.');
  }
  this._maxListeners = n;
  return this;
};

function _getMaxListeners(that) {
  if (that._maxListeners === undefined)
    return EventEmitter.defaultMaxListeners;
  return that._maxListeners;
}

EventEmitter.prototype.getMaxListeners = function getMaxListeners() {
  return _getMaxListeners(this);
};

EventEmitter.prototype.emit = function emit(type) {
  var args = [];
  for (var i = 1; i < arguments.length; i++) args.push(arguments[i]);
  var doError = (type === 'error');

  var events = this._events;
  if (events !== undefined)
    doError = (doError && events.error === undefined);
  else if (!doError)
    return false;

  // If there is no 'error' event listener then throw.
  if (doError) {
    var er;
    if (args.length > 0)
      er = args[0];
    if (er instanceof Error) {
      // Note: The comments on the `throw` lines are intentional, they show
      // up in Node's output if this results in an unhandled exception.
      throw er; // Unhandled 'error' event
    }
    // At least give some kind of context to the user
    var err = new Error('Unhandled error.' + (er ? ' (' + er.message + ')' : ''));
    err.context = er;
    throw err; // Unhandled 'error' event
  }

  var handler = events[type];

  if (handler === undefined)
    return false;

  if (typeof handler === 'function') {
    ReflectApply(handler, this, args);
  } else {
    var len = handler.length;
    var listeners = arrayClone(handler, len);
    for (var i = 0; i < len; ++i)
      ReflectApply(listeners[i], this, args);
  }

  return true;
};

function _addListener(target, type, listener, prepend) {
  var m;
  var events;
  var existing;

  checkListener(listener);

  events = target._events;
  if (events === undefined) {
    events = target._events = Object.create(null);
    target._eventsCount = 0;
  } else {
    // To avoid recursion in the case that type === "newListener"! Before
    // adding it to the listeners, first emit "newListener".
    if (events.newListener !== undefined) {
      target.emit('newListener', type,
                  listener.listener ? listener.listener : listener);

      // Re-assign `events` because a newListener handler could have caused the
      // this._events to be assigned to a new object
      events = target._events;
    }
    existing = events[type];
  }

  if (existing === undefined) {
    // Optimize the case of one listener. Don't need the extra array object.
    existing = events[type] = listener;
    ++target._eventsCount;
  } else {
    if (typeof existing === 'function') {
      // Adding the second element, need to change to array.
      existing = events[type] =
        prepend ? [listener, existing] : [existing, listener];
      // If we've already got an array, just append.
    } else if (prepend) {
      existing.unshift(listener);
    } else {
      existing.push(listener);
    }

    // Check for listener leak
    m = _getMaxListeners(target);
    if (m > 0 && existing.length > m && !existing.warned) {
      existing.warned = true;
      // No error code for this since it is a Warning
      // eslint-disable-next-line no-restricted-syntax
      var w = new Error('Possible EventEmitter memory leak detected. ' +
                          existing.length + ' ' + String(type) + ' listeners ' +
                          'added. Use emitter.setMaxListeners() to ' +
                          'increase limit');
      w.name = 'MaxListenersExceededWarning';
      w.emitter = target;
      w.type = type;
      w.count = existing.length;
      ProcessEmitWarning(w);
    }
  }

  return target;
}

EventEmitter.prototype.addListener = function addListener(type, listener) {
  return _addListener(this, type, listener, false);
};

EventEmitter.prototype.on = EventEmitter.prototype.addListener;

EventEmitter.prototype.prependListener =
    function prependListener(type, listener) {
      return _addListener(this, type, listener, true);
    };

function onceWrapper() {
  if (!this.fired) {
    this.target.removeListener(this.type, this.wrapFn);
    this.fired = true;
    if (arguments.length === 0)
      return this.listener.call(this.target);
    return this.listener.apply(this.target, arguments);
  }
}

function _onceWrap(target, type, listener) {
  var state = { fired: false, wrapFn: undefined, target: target, type: type, listener: listener };
  var wrapped = onceWrapper.bind(state);
  wrapped.listener = listener;
  state.wrapFn = wrapped;
  return wrapped;
}

EventEmitter.prototype.once = function once(type, listener) {
  checkListener(listener);
  this.on(type, _onceWrap(this, type, listener));
  return this;
};

EventEmitter.prototype.prependOnceListener =
    function prependOnceListener(type, listener) {
      checkListener(listener);
      this.prependListener(type, _onceWrap(this, type, listener));
      return this;
    };

// Emits a 'removeListener' event if and only if the listener was removed.
EventEmitter.prototype.removeListener =
    function removeListener(type, listener) {
      var list, events, position, i, originalListener;

      checkListener(listener);

      events = this._events;
      if (events === undefined)
        return this;

      list = events[type];
      if (list === undefined)
        return this;

      if (list === listener || list.listener === listener) {
        if (--this._eventsCount === 0)
          this._events = Object.create(null);
        else {
          delete events[type];
          if (events.removeListener)
            this.emit('removeListener', type, list.listener || listener);
        }
      } else if (typeof list !== 'function') {
        position = -1;

        for (i = list.length - 1; i >= 0; i--) {
          if (list[i] === listener || list[i].listener === listener) {
            originalListener = list[i].listener;
            position = i;
            break;
          }
        }

        if (position < 0)
          return this;

        if (position === 0)
          list.shift();
        else {
          spliceOne(list, position);
        }

        if (list.length === 1)
          events[type] = list[0];

        if (events.removeListener !== undefined)
          this.emit('removeListener', type, originalListener || listener);
      }

      return this;
    };

EventEmitter.prototype.off = EventEmitter.prototype.removeListener;

EventEmitter.prototype.removeAllListeners =
    function removeAllListeners(type) {
      var listeners, events, i;

      events = this._events;
      if (events === undefined)
        return this;

      // not listening for removeListener, no need to emit
      if (events.removeListener === undefined) {
        if (arguments.length === 0) {
          this._events = Object.create(null);
          this._eventsCount = 0;
        } else if (events[type] !== undefined) {
          if (--this._eventsCount === 0)
            this._events = Object.create(null);
          else
            delete events[type];
        }
        return this;
      }

      // emit removeListener for all listeners on all events
      if (arguments.length === 0) {
        var keys = Object.keys(events);
        var key;
        for (i = 0; i < keys.length; ++i) {
          key = keys[i];
          if (key === 'removeListener') continue;
          this.removeAllListeners(key);
        }
        this.removeAllListeners('removeListener');
        this._events = Object.create(null);
        this._eventsCount = 0;
        return this;
      }

      listeners = events[type];

      if (typeof listeners === 'function') {
        this.removeListener(type, listeners);
      } else if (listeners !== undefined) {
        // LIFO order
        for (i = listeners.length - 1; i >= 0; i--) {
          this.removeListener(type, listeners[i]);
        }
      }

      return this;
    };

function _listeners(target, type, unwrap) {
  var events = target._events;

  if (events === undefined)
    return [];

  var evlistener = events[type];
  if (evlistener === undefined)
    return [];

  if (typeof evlistener === 'function')
    return unwrap ? [evlistener.listener || evlistener] : [evlistener];

  return unwrap ?
    unwrapListeners(evlistener) : arrayClone(evlistener, evlistener.length);
}

EventEmitter.prototype.listeners = function listeners(type) {
  return _listeners(this, type, true);
};

EventEmitter.prototype.rawListeners = function rawListeners(type) {
  return _listeners(this, type, false);
};

EventEmitter.listenerCount = function(emitter, type) {
  if (typeof emitter.listenerCount === 'function') {
    return emitter.listenerCount(type);
  } else {
    return listenerCount.call(emitter, type);
  }
};

EventEmitter.prototype.listenerCount = listenerCount;
function listenerCount(type) {
  var events = this._events;

  if (events !== undefined) {
    var evlistener = events[type];

    if (typeof evlistener === 'function') {
      return 1;
    } else if (evlistener !== undefined) {
      return evlistener.length;
    }
  }

  return 0;
}

EventEmitter.prototype.eventNames = function eventNames() {
  return this._eventsCount > 0 ? ReflectOwnKeys(this._events) : [];
};

function arrayClone(arr, n) {
  var copy = new Array(n);
  for (var i = 0; i < n; ++i)
    copy[i] = arr[i];
  return copy;
}

function spliceOne(list, index) {
  for (; index + 1 < list.length; index++)
    list[index] = list[index + 1];
  list.pop();
}

function unwrapListeners(arr) {
  var ret = new Array(arr.length);
  for (var i = 0; i < ret.length; ++i) {
    ret[i] = arr[i].listener || arr[i];
  }
  return ret;
}

function once(emitter, name) {
  return new Promise(function (resolve, reject) {
    function errorListener(err) {
      emitter.removeListener(name, resolver);
      reject(err);
    }

    function resolver() {
      if (typeof emitter.removeListener === 'function') {
        emitter.removeListener('error', errorListener);
      }
      resolve([].slice.call(arguments));
    };

    eventTargetAgnosticAddListener(emitter, name, resolver, { once: true });
    if (name !== 'error') {
      addErrorHandlerIfEventEmitter(emitter, errorListener, { once: true });
    }
  });
}

function addErrorHandlerIfEventEmitter(emitter, handler, flags) {
  if (typeof emitter.on === 'function') {
    eventTargetAgnosticAddListener(emitter, 'error', handler, flags);
  }
}

function eventTargetAgnosticAddListener(emitter, name, listener, flags) {
  if (typeof emitter.on === 'function') {
    if (flags.once) {
      emitter.once(name, listener);
    } else {
      emitter.on(name, listener);
    }
  } else if (typeof emitter.addEventListener === 'function') {
    // EventTarget does not have `error` event semantics like Node
    // EventEmitters, we do not listen for `error` events here.
    emitter.addEventListener(name, function wrapListener(arg) {
      // IE does not have builtin `{ once: true }` support so we
      // have to do it manually.
      if (flags.once) {
        emitter.removeEventListener(name, wrapListener);
      }
      listener(arg);
    });
  } else {
    throw new TypeError('The "emitter" argument must be of type EventEmitter. Received type ' + typeof emitter);
  }
}

},{}],91:[function(require,module,exports){
/*! ieee754. BSD-3-Clause License. Feross Aboukhadijeh <https://feross.org/opensource> */
exports.read = function (buffer, offset, isLE, mLen, nBytes) {
  var e, m
  var eLen = (nBytes * 8) - mLen - 1
  var eMax = (1 << eLen) - 1
  var eBias = eMax >> 1
  var nBits = -7
  var i = isLE ? (nBytes - 1) : 0
  var d = isLE ? -1 : 1
  var s = buffer[offset + i]

  i += d

  e = s & ((1 << (-nBits)) - 1)
  s >>= (-nBits)
  nBits += eLen
  for (; nBits > 0; e = (e * 256) + buffer[offset + i], i += d, nBits -= 8) {}

  m = e & ((1 << (-nBits)) - 1)
  e >>= (-nBits)
  nBits += mLen
  for (; nBits > 0; m = (m * 256) + buffer[offset + i], i += d, nBits -= 8) {}

  if (e === 0) {
    e = 1 - eBias
  } else if (e === eMax) {
    return m ? NaN : ((s ? -1 : 1) * Infinity)
  } else {
    m = m + Math.pow(2, mLen)
    e = e - eBias
  }
  return (s ? -1 : 1) * m * Math.pow(2, e - mLen)
}

exports.write = function (buffer, value, offset, isLE, mLen, nBytes) {
  var e, m, c
  var eLen = (nBytes * 8) - mLen - 1
  var eMax = (1 << eLen) - 1
  var eBias = eMax >> 1
  var rt = (mLen === 23 ? Math.pow(2, -24) - Math.pow(2, -77) : 0)
  var i = isLE ? 0 : (nBytes - 1)
  var d = isLE ? 1 : -1
  var s = value < 0 || (value === 0 && 1 / value < 0) ? 1 : 0

  value = Math.abs(value)

  if (isNaN(value) || value === Infinity) {
    m = isNaN(value) ? 1 : 0
    e = eMax
  } else {
    e = Math.floor(Math.log(value) / Math.LN2)
    if (value * (c = Math.pow(2, -e)) < 1) {
      e--
      c *= 2
    }
    if (e + eBias >= 1) {
      value += rt / c
    } else {
      value += rt * Math.pow(2, 1 - eBias)
    }
    if (value * c >= 2) {
      e++
      c /= 2
    }

    if (e + eBias >= eMax) {
      m = 0
      e = eMax
    } else if (e + eBias >= 1) {
      m = ((value * c) - 1) * Math.pow(2, mLen)
      e = e + eBias
    } else {
      m = value * Math.pow(2, eBias - 1) * Math.pow(2, mLen)
      e = 0
    }
  }

  for (; mLen >= 8; buffer[offset + i] = m & 0xff, i += d, m /= 256, mLen -= 8) {}

  e = (e << mLen) | m
  eLen += mLen
  for (; eLen > 0; buffer[offset + i] = e & 0xff, i += d, e /= 256, eLen -= 8) {}

  buffer[offset + i - d] |= s * 128
}

},{}]},{},[86]);
