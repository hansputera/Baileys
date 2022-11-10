// original code: https://gist.github.com/PurpShell/44433d21631ff0aefbea57f7b5e31139

export const getCrypto = (): Crypto => {
	const c = require('crypto')

	return 'subtle' in (c?.webcrypto || {}) ? c.webcrypto : new (require('@peculiar/webcrypto').Crypto)()
}

/**
     * Compare the SHA-256 hashes of the poll options from the update to find the original choices
     * @param options Options from the poll creation message
     * @param pollOptionHash hash from `decryptPollMessageRaw()`
     * @return {Promise<string[]>} the original option, can be empty when none are currently selected
     */
export const comparePollMessage = async(options: string[], pollOptionHashes: string[]): Promise<string[]> => {
	const selectedOptions: string[] = []
	const crypto = getCrypto()
	for(const option of options) {
		const hash = Buffer
			.from(
				await crypto.subtle.digest(
					'SHA-256',
					(new TextEncoder).encode(option)
				)
			)
			.toString('hex').toUpperCase()

		if(pollOptionHashes.findIndex(h => h === hash) > -1) {
			selectedOptions.push(option)
		}
	}

	;
	return selectedOptions
}

/**
     * Raw method to decrypt the message after gathering all information
     * @description Use `decryptPollMessage()` instead, only use this if you know what you are doing
     * @param encPayload Vote encrypted payload
     * @param encIv vote encrypted iv
     * @param additionalData poll additional data
     * @param decryptionKey generated decryption key
     * @return {Promise<Uint8Array>}
     */
const decryptPollMessageInternal = async(
	encPayload: Uint8Array,
	encIv: Uint8Array,
	additionalData: Uint8Array,
	decryptionKey: Uint8Array,
): Promise<Uint8Array> => {
	const crypto = getCrypto()

	const tagSize_multiplier = 16
	const encoded = encPayload
	const key = await crypto.subtle.importKey('raw', decryptionKey, 'AES-GCM', false, ['encrypt', 'decrypt'])
	const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: encIv, additionalData: additionalData, tagLength: 8 * tagSize_multiplier }, key, encoded)
	return new Uint8Array(decrypted).slice(2) // remove 2 bytes (OA20)(space+newline)
}

/**
     * Decode the message from `decryptPollMessageInternal()`
     * @param decryptedMessage the message from `decrpytPollMessageInternal()`
     * @return {string}
     */
export const decodePollMessage = (decryptedMessage: Uint8Array): string => {
	const n = [48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 65, 66, 67, 68, 69, 70]
	const outarr: number[] = []

	for(let i = 0; i < decryptedMessage.length; i++) {
		const val = decryptedMessage[i]
		outarr.push(n[val >> 4], n[15 & val])
	}

	return String.fromCharCode(...outarr)
}

/**
     * decrypt a poll message update
     * @param encPayload from the update
     * @param encIv from the update
     * @param encKey from the original poll
     * @param pollMsgSender sender jid of the pollCreation message
     * @param pollMsgId id of the pollCreation message
     * @param voteMsgSender sender of the pollUpdate message
     * @return {Promise<string[]>} The option or empty array if something went wrong OR everything was unticked
     */
export const decryptPollMessageRaw = async(
	encKey: Uint8Array,
	encPayload: Uint8Array,
	encIv: Uint8Array,
	pollMsgSender: string,
	pollMsgId: string,
	voteMsgSender: string
): Promise<string[]> => {
	const enc = new TextEncoder()
	const crypto = getCrypto()

	const stanzaId = enc.encode(pollMsgId)
	const parentMsgOriginalSender = enc.encode(pollMsgSender)
	const modificationSender = enc.encode(voteMsgSender)
	const modificationType = enc.encode('Poll Vote')
	const pad = new Uint8Array([1])

	const signMe = new Uint8Array([...stanzaId, ...parentMsgOriginalSender, ...modificationSender, ...modificationType, pad] as any)

	const createSignKey = async(n: Uint8Array = new Uint8Array(32)) => {
		return (await crypto.subtle.importKey('raw', n,
			{ 'name': 'HMAC', 'hash': 'SHA-256' }, false, ['sign']
		))
	}

	const sign = async(n: Uint8Array, key: CryptoKey) => {
		return (await crypto.subtle.sign({ 'name': 'HMAC', 'hash': 'SHA-256' }, key, n))
	}

	let key = await createSignKey()

	const temp = await sign(encKey, key)

	key = await createSignKey(new Uint8Array(temp))

	const decryptionKey = new Uint8Array(await sign(signMe, key))

	const additionalData = enc.encode(`${pollMsgId}\u0000${voteMsgSender}`)

	const decryptedMessage = await decryptPollMessageInternal(encPayload, encIv, additionalData, decryptionKey)

	const pollOptionHash = decodePollMessage(decryptedMessage)

	// '0A20' in hex represents unicode " " and "\n" thus declaring the end of one option
	// we want multiple hashes to make it easier to iterate and understand for your use cases
	return pollOptionHash.split('0A20') || []
}
