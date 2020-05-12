const enc = new TextEncoder(),
	dec = new TextDecoder();

class CryptoStuff {
	//https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto

	static async get_dh_keypair(){
		return window.crypto.subtle.generateKey(
			{
		      name: "ECDH",
		      namedCurve: "P-384"
		    },
		    true,
		    ["deriveKey"]
		);
	}

	static async generate_dh_shared_key(myPrivateKey, theirPublicKey){
		return window.crypto.subtle.deriveKey(
		    {
		      name: "ECDH",
		      public: theirPublicKey
		    },
		    myPrivateKey,
		    {
		    	name: "AES-GCM",
		    	length: 256
		    },
		    true,
		    ["encrypt", "decrypt"]
		);
	}

	static async encrypt(decryptedMsg, key, iv){
		// https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/decrypt
		// https://github.com/mdn/dom-examples/blob/master/web-crypto/derive-key/ecdh.js

		let msg = enc.encode(decryptedMsg),
			encryptedMsgBuffer = await window.crypto.subtle.encrypt(
			    {
		          name: "AES-GCM",
		          iv: iv
		        },
			    key,
			    msg
		    ),
		    encryptedMsg = CryptoStuff.arrayBufferToHex(encryptedMsgBuffer);
		return encryptedMsg
	}

	static async decrypt(encryptedMsg, key, iv){
		// https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/decrypt
		// https://github.com/mdn/dom-examples/blob/master/web-crypto/derive-key/ecdh.js
		
		try {
			let encryptedMsgBuffer = CryptoStuff.hexToArrayBuffer(encryptedMsg),
				decrypted = await window.crypto.subtle.decrypt(
			        {
			          name: "AES-GCM",
			          iv: iv
			        },
			        key,
			        encryptedMsgBuffer
		        );
	        return dec.decode(decrypted);

	    } catch (e) {
	    	alert('Error: decryption error.');
	    }
	}

	static async hash(toHash){
		// https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/digest
		let hashEnc = enc.encode(toHash),                        				  
			hashBuffer = await crypto.subtle.digest('SHA-256', hashEnc),
			keyHex = CryptoStuff.arrayBufferToHex(hashBuffer);

		return keyHex;
	}

	static arrayBufferToHex(arrayBuffer){
		let intArray = new Uint8Array(arrayBuffer),
			hashArray = Array.from(intArray),
			hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');

		return hashHex;
	}

	static hexToArrayBuffer(hex){
		let array = []; 
		for (let i=0; i<hex.length; i+=2){
			let hexNum = hex.substring(i,i+2),
				decimal = parseInt(hexNum, 16);

			array.push(decimal);
		}
		let buffer = new Uint8Array(array).buffer;

		return buffer;
	}

	static async exportKey(key){
		let keyBuffer = await window.crypto.subtle.exportKey(
			    "raw",
			    key
			),
			keyHex = CryptoStuff.arrayBufferToHex(keyBuffer);

		return keyHex;
	}

	static async importKey_dh(keyHex){
		let keyBuff = CryptoStuff.hexToArrayBuffer(keyHex);

		let key =  window.crypto.subtle.importKey(
		    "raw",
		    keyBuff,
		    {
		    	name: "ECDH",
		    	namedCurve: "P-384"
		    },
		    true,
		    []
		);
		return key;
	}

  static async importKey_aes_gcm(keyHex){
		let keyBuff = CryptoStuff.hexToArrayBuffer(keyHex);

		let key =  window.crypto.subtle.importKey(
		    "raw",
		    keyBuff,
		    {
		    	name: "ECDH",
		    	namedCurve: "P-384"
		    },
		    true,
		    []
		);
		return key;
	}

	static async generate_iv(){
		return window.crypto.getRandomValues(new Uint8Array(12));
	}

	static async rawStringToKey(str){
		let strEnc = enc.encode(str);
	  
		let keyDigest = await window.crypto.subtle.digest(
	    	{name: 'SHA-256'},
	    	passEnc
	    );

	    let key = await window.crypto.subtle.importKey(
		    'raw',
		    keyDigest,
		    {name: "AES-GCM"},
		    true,
		    ['encrypt', 'decrypt']
	    );
	    return key;
	}
}

class Person{
    constructor(name){
      this.name = name;
    }

    async generateKeys(){
      let keypair = await CryptoStuff.get_dh_keypair();
      this.publicKey = keypair.publicKey;
      this.privateKey = keypair.privateKey;
    }

    async receiveMessage(msg){
      msg = JSON.parse(msg);

      switch (this.sharedKey){
        case undefined:
          await this.receiveHandshake(msg.publicKey);
          break;

        default:
          let iv = CryptoStuff.hexToArrayBuffer(msg.iv),
            text = await CryptoStuff.decrypt(msg.message, this.sharedKey, iv);

          console.log(`***${this.name} decrypted message: ${text}***\n
          `);
      }
    }

    async sendEncryptedMessage(msg, recipient){
      console.log(`***${this.name} encrypted message: ${msg}***
      `);

      let iv = await CryptoStuff.generate_iv(),
        ivStr = CryptoStuff.arrayBufferToHex(iv),
        msgStr = await CryptoStuff.encrypt(msg, this.sharedKey, iv);

      sendMessage({
        message: msgStr,
        iv: ivStr
      }, recipient, this);
  }

    async giveHandshake(recipient){
      let publicKeyStr = await CryptoStuff.exportKey(this.publicKey);
      await sendMessage({publicKey: publicKeyStr}, recipient, this);
    }

    async receiveHandshake(publicKeyStr){
      return new Promise(async (resolve) => {
        let publicKey = await CryptoStuff.importKey_dh(publicKeyStr);

        this.sharedKey = await CryptoStuff.generate_dh_shared_key(
          this.privateKey, 
          publicKey
        );
        resolve();
      });
    }

}

async function sendMessage(msg, to, from){
  msg = JSON.stringify(msg);
  console.log(`sending an encrypted message:
    from: ${from.name}
    to: ${to.name}
    message: ${msg}
    `
  );
  await to.receiveMessage(msg);
}

async function test(){
  let alice = new Person('Alice'),
    bob = new Person('Bob');

  await alice.generateKeys();
  await bob.generateKeys();

  // alice and bob can only talk through the sendMessage function

  await alice.giveHandshake(bob);
  await bob.giveHandshake(alice);
  await alice.sendEncryptedMessage('Hello there Bob!', bob);
}



/*async function test(){

  let alicesKeyPair = await CryptoStuff.get_dh_keypair(),
    alicesPublicKey = alicesKeyPair.publicKey,
    alicesPrivateKey = alicesKeyPair.privateKey;

  let bobsKeyPair = await CryptoStuff.get_dh_keypair(),
    bobsPublicKey = bobsKeyPair.publicKey,
    bobsPrivateKey = bobsKeyPair.privateKey;

  let alicesPublicKeyExported = await CryptoStuff.dh_keyToString(alicesPublicKey),
    alicesPublicKeyImported = await CryptoStuff.dh_stringToKey(alicesPublicKeyExported);

  let bobsPublicKeyExported = await CryptoStuff.dh_keyToString(bobsPublicKey),
    bobsPublicKeyImported = await CryptoStuff.dh_stringToKey(bobsPublicKeyExported);

  let alicesSharedKey = await CryptoStuff.generate_dh_shared_key(alicesPrivateKey, bobsPublicKeyImported),
    alicesSharedKeyStr = await CryptoStuff.dh_keyToString(alicesSharedKey);

  let bobsSharedKey = await CryptoStuff.generate_dh_shared_key(bobsPrivateKey, alicesPublicKeyImported),
    bobsSharedKeyStr = await CryptoStuff.dh_keyToString(bobsSharedKey);

  console.log("Alice's shared key:", alicesSharedKeyStr, "\nBob's shared key:  ", bobsSharedKeyStr);
  
  alicesMsg = "Hello there Bob!";
  console.log("Alice's sent message:  ", alicesMsg);

  iv = window.crypto.getRandomValues(new Uint8Array(12));

  let alicesMsgEncrypted = await CryptoStuff.encrypt(alicesMsg, alicesSharedKey, iv); //encrypt with alice's key
  let alicesMsgDecrypted = await CryptoStuff.decrypt(alicesMsgEncrypted, bobsSharedKey, iv); //decrypt with bob's key
  console.log("Bob's received message:", alicesMsgDecrypted);

}*/

test();
 
async function passwordToKey(pass){
  let passEnc = enc.encode(pass);

  let keyDigest = await window.crypto.subtle.digest(
    {name: 'SHA-256'},
    passEnc
  );

  console.log('keyDigest:', CryptoStuff.arrayBufferToHex(keyDigest));

  let key = await window.crypto.subtle.importKey(
    'raw',
    keyDigest,
    {name: "AES-GCM"},
    true,
    ['encrypt', 'decrypt']
  );

  console.log('key:      ', await CryptoStuff.exportKey(key));
  return key;
}

async function encryptMsg(msg, password){
  let key = await passwordToKey('key');
  //console.log('key:', key);

  let iv = await CryptoStuff.generate_iv(),
    encryptedMsg = await CryptoStuff.encrypt(msg, key, iv);

  console.log('encrypted msg:', encryptedMsg);
  
  let decryptedMsg = await CryptoStuff.decrypt(encryptedMsg, key, iv);

  console.log('decrypted msg:', decryptedMsg);
}

//encryptMsg('hey', 'password');

var a = 'a'
async function function1(){
  await new Promise((resolve) => {
    let x = 0;
    while (x<10**6){
      x += 1;
    }
    resolve();
  });
  a = 'b'
}

/*async function function2(){
  console.log('started');
  await function1();
  console.log(a);
}

function2();*/