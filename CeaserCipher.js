/**
 *	File: 		CeaserCipher.js
 *	Description: 
 *				Ceaser Cipher is one of the oldest encryption algorithm. It encrypt the ASCII characters by
 *				shifting the characters by a specific offfset inside the ASCII table.
 *
 *	Author: 	Ritesh Kukreja
 *	Website: 	riteshkukreja.wordpress.com
 */

var CeaserCipher = function() {

	/**
	 *	==================================================================
	 * 							Utilities Methods
	 *	==================================================================
	 */

	/**
	 *	To Replace a string of characters at any positions - makes life easier
	 *	@Param index 		- position of start of string
	 *	@Param character 	- list of characters or string
	 */
	String.prototype.replaceAt=function(index, character) {
	    return this.substr(0, parseInt(index)) + character + this.substr(parseInt(index)+character.length);
	}

	/**
	 *	Generate Modulus of a Number 'num' with Modulo 'modval'
	 *	@Param num 		- Integer to be modulated
	 *	@Param modval	- Modulo Integer
	 */
	var MOD = function(num, modval) {
		return (num < 0 ? MOD(modval+num, modval) : num % modval);
	}

	/**
	 *	Generate a random floating point number in a range fixed to 2 decimal point accuracy
	 *	@Param min 	- Lower Bound (inclusive)
	 *	@Param max 	- Upper Bound (exclusive)
	 */
	var randomFloat = function(min, max) {
		return parseFloat(Math.random() * (max-min+1)).toFixed(2) + min;
	}

	/**
	 *	Limit a number to the given range
	 *	@Param min 	- Lower Bound (inclusive)
	 *	@Param max 	- Upper Bound (exclusive)
	 *	@Param num 	- Integer
	 */
	var limitTo = function(min, max, num) {
		num = MOD(num, max-min);


		if(num < min) num = max - (min - num);
		else if (num >= max) num = (num - max) + min;
		
		return num;
	}

	/**
	 *	Generate a array based sample for the given message or based on previously defined sample in 'LetterFrequency'
	 *	Counts occurance of each character in the message and produce percentage of occurance of the character.
	 *	@Param msg 	- Message String (Optional)
	 */
	var getSampleFrequency = function(msg) {
		var obj = {};

		if(typeof msg == "undefined") {
			for(var i = 32; i < 127; i++) {
				if(typeof LetterFrequency[i] == "undefined")
					obj[i] = parseFloat(randomFloat(0, 1));
				else
					obj[i] = parseFloat(LetterFrequency[i]);
			}
		} else {
			for(char in msg) {
				if(typeof obj[msg.charCodeAt(char)] == "undefined")
					obj[msg.charCodeAt(char)] = 1;
				else
					obj[msg.charCodeAt(char)]++;
			}

			var mul = 100 / msg.length;

			for(i of Object.keys(obj)) {
				obj[i] = parseFloat(obj[i]) * mul;
				obj[i] = parseFloat(obj[i].toFixed(2));
			}
		}

		return obj;
	}

	/**
	 *	Crack the Cipher by generating all Offsets and chosing the one that produce minimum error.
	 *	It's typical way of mapping the message sample on predefined sample to figure out the shift.
	 *	@Param sampled 	- Sample Frequency of the encrypted message
	 *	@Param stored	- Predefined Sample Frequency
	 */
	var cracker = function(sampled, stored) {

		var minOffset = 0, minerror = 999999;
		for(var offset = 0; offset < 126; offset++) {

			var error = genError(sampled, stored, offset);

			if(error < minerror) {
				minOffset = offset;
				minerror = error;
			}
		}

		return minOffset;
	}

	/**
	 *	Generate Error by mapping the message sample on predefined sample with a specific shift.
	 *	@Param sampled 	- Sample Frequency of the encrypted message
	 *	@Param stored	- Predefined Sample Frequency
	 *	@Param offset 	- Best bet of Shift
	 */
	var genError = function(sampled, stored, offset) {
		var error = 0;

		for(key of Object.keys(sampled)) {
			var pKey;

			if(parseInt(key) - offset < 32)
			  pKey = limitTo(32, 127, parseInt(key) - offset);
			else
			  pKey = parseInt(key) - offset;

			if(typeof sampled[key] == "undefined" || typeof stored[pKey] == "undefined") continue;
			else error += Math.abs(sampled[key] - stored[pKey]);
		}

		return error;
	}

	/**
	 *	==================================================================
	 * 							Prototype Methods
	 *	==================================================================
	 */

	/**
	 *	Encryption Method to encrypt the message with a specific shift.
	 *	@Param msg 		- Message String to be encrypted
	 *	@Param cshift	- Given Shift
	 */
	this.encrypt = function (msg, cshift) {
		for(key = 0; key < msg.length; key++) {
			var code = msg.charCodeAt(key);
			code = limitTo(32, 127, (code + cshift));

			msg = msg.replaceAt(key, String.fromCharCode(code));
		}

		return msg;
	}

	/**
	 *	Decryption Method to decrypt the message with a specific shift.
	 *	@Param encmsg 	- Cipher String to be decrypted
	 *	@Param cshift	- Given Shift
	 */
	this.decrypt = function (encmsg, cshift) {
		for(key = 0; key < encmsg.length; key++) {

			var code = encmsg.charCodeAt(key);
			code = limitTo(32, 127, (code - cshift));

			encmsg = encmsg.replaceAt(key, String.fromCharCode(code));

		}

		return encmsg;
	}

	/**
	 *	Cracking Algorithm to figure out the shift used in encryption.
	 *	@Param encmsg 	- Cipher String to be decrypted
	 */
	this.crack = function(encmsg) {
		var stored = getSampleFrequency();
		var sampled = getSampleFrequency(encmsg);

		var minOffset = cracker(sampled, stored);
		console.log(minOffset);

		return this.decrypt(encmsg, minOffset);
	}

}