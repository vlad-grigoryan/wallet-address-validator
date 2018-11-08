var bcrypto = require('bcrypto');
var base58 = require('./crypto/base58');
var cryptoUtils = require('./crypto/utils');
var Buffer = require('safe-buffer').Buffer;

var DEFAULT_NETWORK_TYPE = 'prod';

function getDecoded(address) {
    try {
        return base58.decode(address);
    } catch (e) {
        // if decoding fails, assume invalid address
        return null;
    }
}

function getChecksum(hashFunction, payload) {
    // Each currency may implement different hashing algorithm
    switch (hashFunction) {
        case 'blake256':
            return cryptoUtils.blake256Checksum(payload);
            break;
        case 'sha256':
        default:
            return cryptoUtils.sha256Checksum(payload);
    }
}

function getAddressType(address, currency) {
    currency = currency || {};
    // should be 25 bytes per btc address spec and 26 decred
    var expectedLength = currency.expectedLength || 25;
    var hashFunction = currency.hashFunction || 'sha256';
    var decoded = getDecoded(address);

    if (decoded) {
        var length = decoded.length;

        if (length !== expectedLength) {
            return null;
        }

        var checksum = cryptoUtils.toHex(decoded.slice(length - 4, length)),
            body = cryptoUtils.toHex(decoded.slice(0, length - 4)),
            goodChecksum = getChecksum(hashFunction, body);

        return checksum === goodChecksum ? cryptoUtils.toHex(decoded.slice(0, expectedLength - 24)) : null;
    }

    return null;
}

function isValidP2PKHandP2SHAddress(address, currency, networkType) {
    networkType = networkType || DEFAULT_NETWORK_TYPE;

    var correctAddressTypes;
    var addressType = getAddressType(address, currency);

    if (addressType) {
        if (networkType === 'prod' || networkType === 'testnet') {
            correctAddressTypes = currency.addressTypes[networkType]
        } else {
            correctAddressTypes = currency.addressTypes.prod.concat(currency.addressTypes.testnet);
        }

        return correctAddressTypes.indexOf(addressType) >= 0;
    }

    return false;
}

module.exports = {
    isValidAddress: function (address, currency, networkType) {
        var expectedLength = currency.expectedLength;
        var decoded = getDecoded(address);
        var correctAddressTypes;
        var addressType;
        var version;

        if (decoded) {
            var length = decoded.length;

            if (length !== expectedLength) {
                return false;
            }
            addressType = cryptoUtils.toHex(decoded.slice(1, 2));
            version = cryptoUtils.toHex(decoded.slice(0, 1));

            if (version !== currency.version) {
                return false;
            }
        }

        if (networkType === 'prod' || networkType === 'testnet') {
            correctAddressTypes = currency.addressTypes[networkType]
        } else {
            correctAddressTypes = currency.addressTypes.prod.concat(currency.addressTypes.testnet);
        }

        if (correctAddressTypes.indexOf(addressType) >= 0) {
            return this.verifyChecksum(decoded);
        }

        return false;
    },
    verifyChecksum: function(bytes) {
        var blake256digest = bcrypto.BLAKE2b256.digest(Buffer.from(bytes.slice(0, -4)));
        var keccak256 = bcrypto.Keccak256.digest(Buffer.from(blake256digest));
        var computedChecksum = keccak256.toString('hex').slice(0, 8);
        var checksum = cryptoUtils.toHex(bytes.slice(-4));

        return computedChecksum === checksum;
    }
};
