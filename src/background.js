import { MlKem768 } from "crystals-kyber-js";

//create global instance of MLKem
const KEM = new MlKem768();

//------------------------ Gen Keys --------------------------------------------------
// function to generate key pair
async function genKeyPair() {
  try {
    //generate pair
    const [publicKey, secretKey] = await KEM.generateKeyPair();

    // Convert to base64 for easy transmission
    const pkBase64 = btoa(String.fromCharCode(...publicKey));
    const skBase64 = btoa(String.fromCharCode(...secretKey));

    // return all data to frontside
    return {
      success: true,
      publicKey: pkBase64,
      secretKey: skBase64,
      publicKeyLength: publicKey.length,
      secretKeyLength: secretKey.length,
    };

    //catch any errors and return error mssg to frontside
  } catch (error) {
    return {
      success: false,
      error: error.message,
    };
  }
}

//------------------------ ^ Gen Keys ^ --------------------------------------------------

//------------------------ ENCRYPTION --------------------------------------------------

// define AES function to make key
async function findAESKey(secret) {
  const aesKey = await crypto.subtle.importKey(
    "raw", //formatted as raw bytes
    secret, //key data to use
    { name: "AES-GCM" }, // type of algorithm
    false, // doesnt need to be exported
    ["encrypt", "decrypt"], // key operations
  );

  return aesKey;
}

async function encryptMssg(mssg, pkR) {

  // sender generates ct + ssS
  // ct = ciphertext (not the message)
  // ssS = shared secret Sender

  const [ct, ssS] = await KEM.encap(pkR);

  // generate aes key
  const aesKey = await findAESKey(ssS);

  // generate new initialisation vector
  const iv = crypto.getRandomValues(new Uint8Array(12));

  // make instance of textEncoder to translate the messg into utf8
  const encoder = new TextEncoder();
  const udata = encoder.encode(mssg);

  //encrypt the data using aes and the iv
  const eDataRaw = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    aesKey,
    udata,
  );

  // change the raw data into an array of ints
  const eData = new Uint8Array(eDataRaw);

  return {
    ct,
    encMssg: eData,
    iv,
  };
}
//------------------------ ^ ENCRYPTION ^ --------------------------------------------------


//------------------------ DECRYPTION --------------------------------------------------
async function decryptMssg(ct, enMssg, iv, skR) {
  // get from message:
  // - ct
  // - encrypted message
  // - iv
  // - get private key from user input

  // calulate the ssR (ssS == ssR) <- if done correctly
  const ssR = await KEM.decap(ct, skR);

  // calculate the AES key using ssR
  const aesKey = await findAESKey(ssR);

  //decrypt the message
  const decry = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv },
    aesKey,
    enMssg,
  );

  // decode from utf8
  const decoder = new TextDecoder();
  const dMssg = decoder.decode(decry);
  return dMssg;
}

//------------------------ ^ DECRYPTION ^ --------------------------------------------------

// sending data to storage
async function addKGStorageData(newPubKey, newPrivKey) {
  // too add data on, must first get old data, modify array, then "set" new data
  try {
    //fetch the already stored data
    const { pubKeys, privKeys } = await chrome.storage.local.get({
      pubKeys: [],
      privKeys: [],
    });

    // append the new data
    pubKeys.push(newPubKey);
    privKeys.push(newPrivKey);

    // save to storage
    await chrome.storage.local.set({ pubKeys, privKeys });

    return { success: true };
  } catch (error) {
    console.log("Storage set data error:", error);
    alert("Error adding data to storage");
    return { success: false, error: error.message };
  }
}

async function getKGStorageData() {
  try {
    // fetch stored keys
    const { pubKeys, privKeys } = await chrome.storage.local.get({
      pubKeys: [],
      privKeys: [],
    });

    return { success: true, pubKeys, privKeys };
  } catch (error) {
    alert("Error getting data from storage");
    console.log("Error getting stored data:", error);
  }
}

async function setKGStorage(nPubKeys, nPrivKeys) {
  try {

    await chrome.storage.local.set({
      pubKeys: nPubKeys,
      privKeys: nPrivKeys,
    });

    return { success: true };
  } catch (error) {
    alert("Error setting data in storage");
    console.log("Error updating KGStorage in set: ", error);
  }
}

// for resetting the storage
async function clearKGStorage() {
  try {

    // can do this but only deletes set data
    await chrome.storage.local.set({
      pubKeys: [],
      privKeys: [],
    });

    return { success: true };
  } catch (error) {
    alert("Error deleting data from storage");
    return { success: false, error: error.message };
  }
}

//----------------------------------------------------------------------------------

// sending data to storage
async function addKeySData(newKeyRef, newPublicSKey) {

  // too add data on, must first get old data, modify array, then "set" new data

  try {

    //fetch the already stored data
    const { keyRef, publicSKey } = await chrome.storage.local.get({
      keyRef: [],
      publicSKey: [],
    });

    // append the new data
    keyRef.push(newKeyRef);
    publicSKey.push(newPublicSKey);

    // save to storage
    await chrome.storage.local.set({ keyRef, publicSKey });

    return { success: true };
  } catch (error) {
    console.log("KEY Storage set data error:", error);
    alert("Error adding data to storage");
    return { success: false, error: error.message };
  }
}

async function setKeySData(nKeyRef, nPublicSKey) {
  try {
    // overwrite the storage
    await chrome.storage.local.set({
      keyRef: nKeyRef,
      publicSKey: nPublicSKey,
    });

    return { success: true };
  } catch (error) {
    console.log("KEY Storage set data error:", error);
    alert("Error setting data to storage");
    return { success: false, error: error.message };
  }
}

async function getKeySData() {
  try {
    // fetch stored keys
    const { keyRef, publicSKey } = await chrome.storage.local.get({
      keyRef: [],
      publicSKey: [],
    });

    // print the storage as a table
    chrome.storage.local.get(null, (items) => {
      console.table(items);
    });

    return { success: true, keyRef, publicSKey };
  } catch (error) {
    console.log("Error getting stored data:", error);
    alert("Error getting data from storage");
    return { success: false, error: error.message };
  }
}

// for resetting the storage
async function clearKeyS() {
  try {

    // can do this but only deletes set data
    await chrome.storage.local.set({
      keyRef: [],
      publicSKey: [],
    });

    return { success: true };
  } catch (error) {
    alert("Error deleting all reference/key storage");
    return { success: false, error: error.message };
  }
}

//----------------------------------------------------------------------------------

// for completely wiping all storage
async function wipeAllStorageData() {
  try {

    // this completely resets all the local storage
    await chrome.storage.local.clear();

    return { success: true };
  } catch (error) {
    alert("Error deleting all storage");
    return { success: false, error: error.message };
  }
}

//------------------------ ^ Storage test ^ --------------------------------------------------

// -------------------- Listeners --------------------
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  // depending on the action requested, execute the corrosponding case
  switch (request.action) {
    case "genKeys":
      genKeyPair()
        .then(sendResponse)
        .catch((err) => sendResponse({ success: false, error: err.message }));
      return true;

    case "wipeAllData":
      wipeAllStorageData()
        .then(sendResponse)
        .catch((err) => sendResponse({ success: false, error: err.message }));
      return true;

    case "encryptMessage": {
      //get the pk from the key input area and validate
      let { userData, userPK } = request.payload;

      if (userPK == null) {
        console.log("PK for encryption is invalid");
        sendResponse({ success: false, error: "PK given is invalid" });
        return true;
      } else {
        //change the pk back into uint8Array
        const binaryPK = atob(userPK);
        userPK = new Uint8Array(binaryPK.length);
        for (let i = 0; i < binaryPK.length; i++) {
          userPK[i] = binaryPK.charCodeAt(i);
        }
      }

      // if there is a key then use the encryption func to get the correct data
      encryptMssg(userData, userPK)
        // .then takes the output of the function and sends the response back to popup
        .then(({ ct, encMssg, iv }) => {
          sendResponse({
            success: true,
            ct: btoa(String.fromCharCode(...ct)), // formatted from binary into ascii
            iv: btoa(String.fromCharCode(...iv)), // formatted from binary into ascii
            encMssg: btoa(String.fromCharCode(...encMssg)), // formatted from binary into ascii
          });
        })
        .catch((err) => sendResponse({ success: false, error: err.message }));
      return true;
    }

    //decrypt message - encMssg has already been formatted
    case "decryptMssg": {
      let { ct, iv, encMssg, privKey } = request.payload;

      //change the sk back into uint8Array
      privKey = atob(privKey);
      let privKeyArr = new Uint8Array(privKey.length);
      for (let i = 0; i < privKey.length; i++) {
        privKeyArr[i] = privKey.charCodeAt(i);
      }

      //change ct back
      ct = atob(ct);
      let ctArr = new Uint8Array(ct.length);
      for (let i = 0; i < ct.length; i++) {
        ctArr[i] = ct.charCodeAt(i);
      }

      //change encMssg back
      encMssg = atob(encMssg);
      let encMssgArr = new Uint8Array(encMssg.length);
      for (let i = 0; i < encMssg.length; i++) {
        encMssgArr[i] = encMssg.charCodeAt(i);
      }

      // change iv back
      iv = atob(iv);
      let ivArr = new Uint8Array(iv.length);
      for (let i = 0; i < iv.length; i++) {
        ivArr[i] = iv.charCodeAt(i);
      }

      decryptMssg(ctArr, encMssgArr, ivArr, privKeyArr)
        .then((decMssg) => {
          sendResponse({
            success: true,
            decMssg,
          });
        })
        .catch((err) => sendResponse({ success: false, error: err.message }));
      return true;
    }

    case "getKGStorage":
      getKGStorageData()
        .then(sendResponse)
        .catch((err) => sendResponse({ success: false, error: err.message }));
      return true;

    case "setKGStorage":
      const { privKeys, pubKeys } = request.payload;
      setKGStorage(pubKeys, privKeys)
        .then(sendResponse)
        .catch((err) => sendResponse({ success: false, error: err.message }));
      return true;

    case "addKGStorage":
      //get the payload data from message request
      const { pk, sk } = request.payload;
      addKGStorageData(pk, sk)
        .then(sendResponse)
        .catch((err) => sendResponse({ success: false, error: err.message }));
      return true;

    case "resetKGStorage":
      clearKGStorage()
        .then(sendResponse)
        .catch((err) => sendResponse({ success: false, error: err.message }));
      return true;

    // For Public Key Storage
    case "getPKStorage":
      getKeySData()
        .then(sendResponse)
        .catch((err) => sendResponse({ success: false, error: err.message }));
      return true;

    // For Public Key Storage
    case "setKeySData":
      const { keyRef, publicSKey } = request.payload;
      setKeySData(keyRef, publicSKey)
        .then(sendResponse)
        .catch((err) => sendResponse({ success: false, error: err.message }));
      return true;

    // For Public Key Storage
    case "addPKStorage":
      //get the payload data from message request
      const { ref, pubKey } = request.payload;
      addKeySData(ref, pubKey)
        .then(sendResponse)
        .catch((err) => sendResponse({ success: false, error: err.message }));
      return true;

    // For Public Key Storage
    case "resetPKStorage":
      clearKeyS()
        .then(sendResponse)
        .catch((err) => sendResponse({ success: false, error: err.message }));
      return true;

    // to catch any other case or error
    default:
      sendResponse({ success: false, error: "Unknown action" });
      return true;
  }
});
