// ----------- Globals ----------
// seperate selector indexes for each table
let selKGKeyIndex = null;
let selPKKeyIndex = null;

//------------------------------- MAIN PAGE ------------------------------------------------------
async function encryptFromButton() {
  try {
    // get the data given in the text box
    const userData = document.getElementById("inData").value;
    const userPK = document.getElementById("enDeKeyInput").value;

    // extension cannot handle more than 63,832 characters as text input
    if (userData.length > 63000) {
      alert(
        "Encryption Failed - Unfortunately the extension cannot handle more than 63,000 characters. Please shorten your message.",
      );
      return false;
    }

    //validate the length of the key given - public key should always be 1580 characters long
    if (userPK.length != 1580) {
      alert(
        "Encryption Failed - Key length does not match the requirements for a UTF8 encoded ML-KEM768 public key",
      );
      return false;
    }

    // send the action to background with the data in the payload
    const response = await chrome.runtime.sendMessage({
      action: "encryptMessage",
      payload: { userData, userPK },
    });

    if (response.success) {

      // break down the reply into each part
      const { reply, ct, iv, encMssg } = response;

      // format the output with only the data needed
      const formatOutData = `ct = ${ct}\niv = ${iv}\nmssg = ${encMssg}`;

      // format the returned data and put it in the ouput text box
      document.getElementById("outData").value = formatOutData;
    } else {
      alert(
        "Encryption Failed - ensure the key is a valid ML-KEM768 key encoded with utf8",
      );
    }
  } catch (err) {
    console.error("Error Encrypting - ", err);
    alert(
      "Encryption Failed - ensure the key is a valid ML-KEM768 key encoded with utf8",
    );
    return false;
  }
}

async function decryptFromButton() {
  try {
    const rawData = document.getElementById("inData").value;
    const privKey = document.getElementById("enDeKeyInput").value;

    const ct = rawData.split("ct = ")[1].split("\n")[0].trim();
    const iv = rawData.split("iv = ")[1].split("\n")[0].trim();
    const encMssg = rawData.split("mssg = ")[1].split("\n")[0].trim();

    //validate the length of the key given - private key should always be 3200 characters long
    if (privKey.length != 3200) {
      alert(
        "Decryption Failed - Key length does not match the requirements for a UTF8 encoded ML-KEM768 private key",
      );
      return false;
    }

    const response = await chrome.runtime.sendMessage({
      action: "decryptMssg",
      payload: { ct, iv, encMssg, privKey },
    });

    if (response.success) {

      const decMssg = response.decMssg;

      document.getElementById("outData").value = decMssg;
    } else {
      alert(
        "Decryption Failed - ensure the input is formatted 'ct = ' 'mssg = ' 'iv = ' AND the key is a valid ML-KEM768 key encoded with utf8",
      );
    }
  } catch (error) {
    console.log("Error decrypting: ", error);
    alert(
      "Decryption Failed - ensure the input is formatted 'ct = ' 'mssg = ' 'iv = ' AND the key is a valid ML-KEM768 key encoded with utf8",
    );
  }
}

// Shouldve been inline js but extensions arent allowed any
function swapPage(pgNum) {
  var mainP = document.getElementById("mainPgCont");
  var strgP = document.getElementById("storagePgCont");
  var keyP = document.getElementById("keyPgCont");
  var faqP = document.getElementById("faqPgCont");

  mainP.style.display = "none";
  strgP.style.display = "none";
  keyP.style.display = "none";
  faqP.style.display = "none";

  switch (pgNum) {
    case 0:
      mainP.style.display = "block";
      break;

    case 1:
      strgP.style.display = "flex";
      strgP.style.flexDirection = "column";
      getPubKeyTable();
      break;

    case 2:
      keyP.style.display = "flex";
      getKGStorageTable();
      break;

    case 3:
      faqP.style.display = "block";
      break;
  }
}

//--------------------------------------------------------------------------------------------------

//------------------------------- KEY GEN PAGE ------------------------------------------------------

// Function to request new key pair
async function getNewKeyPair() {
  try {
    // call the backside genKeys method
    const response = await chrome.runtime.sendMessage({ action: "genKeys" });

    const response1 = await chrome.runtime.sendMessage({
      action: "addKGStorage",
      payload: { pk: response.publicKey, sk: response.secretKey },
    });

    // if backside returns successfully then...
    if (response.success) {
      const response2 = await chrome.runtime.sendMessage({
        action: "getKGStorage",
      });

      //update table with new data
      getKGStorageTable();
    }

    //if there is an error then print that instead
    else {
      document.getElementById("keyGenOutput").innerHTML =
        `<strong>Error:</strong> ${response.error}`;
    }
  } catch (error) {
    console.error("Error:", error);
    document.getElementById("keyGenOutput").innerHTML =
      `<strong>Error:</strong> ${error.message}`;
    return { success: false };
  }
}

// Gets the stored data and updates the table
async function getKGStorageTable() {
  //get table data
  const response = await chrome.runtime.sendMessage({
    action: "getKGStorage",
  });

  if (response.success) {
    const { pubKeys, privKeys } = response;

    // if the table is empty then exit before the header is shown
    if (pubKeys.length == 0) {
      document.getElementById("storageTable").innerHTML = "";
      return true;
    }

    // get the table from html
    let table = document.getElementById("storageTable");
    // make sure it is empty before adding anything new
    table.innerHTML = "";

    // define the header layout as an element
    const headerRow = document.createElement("tr");
    headerRow.innerHTML = `
    <th>Public Keys</th>
    <th>Private Keys</th>
    `;

    // add the header to the table
    table.appendChild(headerRow);

    // reset the selected index when the table is reloaded
    selKGKeyIndex = null;

    pubKeys.forEach((pk, i) => {
      const row = document.createElement("tr");
      row.innerHTML = `
      <td>${pk.slice(0, 35)}...</td>
      <td>${privKeys[i].slice(0, 35)}...</td>
      `;

      // then for each row add a listener to see if it has been selected
      row.addEventListener("click", () => {
        // unselect all rows
        table
          .querySelectorAll("tr")
          .forEach((rw) => rw.classList.remove("selected"));

        // add selected class to what row was clicked
        row.classList.add("selected");

        //save the index of what was selected
        selKGKeyIndex = i;

      });

      // add each row to the table
      table.appendChild(row);
    });

  } else {
    console.error("Error getting storageTable");
    return { success: false };
  }
}

// fo copying either key from the selected row
async function copyKGKey(isPublic) {

  //check if a row is selected
  if (selKGKeyIndex == null) {
    console.log("No row selected");
    return;
  }

  try {
    const response = await chrome.runtime.sendMessage({
      action: "getKGStorage",
    });

    if (response.success) {
      const { privKeys, pubKeys } = response;

      // if isPublic is true then use pubK array, if false use privK array
      const keyToCopy = isPublic
        ? pubKeys[selKGKeyIndex]
        : privKeys[selKGKeyIndex];

      // write to clipboard
      await navigator.clipboard.writeText(keyToCopy);

    } else {
      console.log("Error getting KG storage for copying");
    }
  } catch (error) {
    console.error("Error copying KG key: ", error);
    return { success: false };
  }
}

async function delKGKey() {
  //check if a row is selected
  if (selKGKeyIndex == null) {
    console.log("No row selected");
    return;
  }

  try {
    const response = await chrome.runtime.sendMessage({
      action: "getKGStorage",
    });

    if (response.success) {
      const { privKeys, pubKeys } = response;

      // delete the selected row from the array
      privKeys.splice(selKGKeyIndex, 1);
      pubKeys.splice(selKGKeyIndex, 1);

      // send the updated arrays back to storage
      await chrome.runtime.sendMessage({
        action: "setKGStorage",
        payload: { privKeys, pubKeys },
      });

      //reset selected row
      selKGKeyIndex = null;

      // update the visable table
      getKGStorageTable();

    } else {
      console.log("Error getting KG keys to delete");
    }
  } catch (error) {
    console.log("Error deleting KG key row: ", error);
    return { success: false };
  }
}

// for testing chrome.storage
async function resetKGStorage() {
  try {
    const response = await chrome.runtime.sendMessage({
      action: "resetKGStorage",
    });

    if (response.success) {

      //update table view with reset table
      getKGStorageTable();
    } else {
      document.getElementById("storageResetAlert").innerHTML =
        `<strong>Error:</strong> ${response.error}`;
    }
  } catch (err) {
    console.error(err);
    return { success: false };
  }
}

//-------------------------------------------------------------------------------------------------------

//------------------------------- KEY STORAGE PAGE ------------------------------------------------------

// get data from storage and format it into the table
async function getPubKeyTable() {

  //get table data
  const response = await chrome.runtime.sendMessage({
    action: "getPKStorage",
  });

  if (response.success) {
    const { keyRef, publicSKey } = response;

    if (keyRef.length == 0) {
      return true;
    }

    // get the table from html
    let table = document.getElementById("pkTable");

    // make sure it is empty before adding anything new
    table.innerHTML = "";

    // define the header
    const headerRow = document.createElement("tr");
    headerRow.innerHTML = `
    <th>Ref.</th>
    <th>Public Keys</th>
    `;

    // add the header to the table
    table.appendChild(headerRow);

    // reset the selected index when the table is reloaded
    selPKKeyIndex = null;

    keyRef.forEach((ref, i) => {
      const row = document.createElement("tr");
      row.innerHTML = `
      <td>${ref.slice(0, 35)}</td>
      <td>${publicSKey[i].slice(0, 35)}...</td>
      `;

      // then for each row add a listener to see if it has been selected
      row.addEventListener("click", () => {

        // unselect all rows
        table
          .querySelectorAll("tr")
          .forEach((rw) => rw.classList.remove("selected"));

        // add selected class to what row was clicked
        row.classList.add("selected");

        //save the index of what was selected
        selPKKeyIndex = i;
      });
      table.appendChild(row);
    });
  } else {
    console.error("Error getting Key Table");
    return { success: false };
  }
}

// adds new ref and key to local storage
async function setPubKeyTable() {
  try {
    //get values from page
    const inRef = document.getElementById("refIn").value;
    const inPubKey = document.getElementById("pkIn").value;

    // validate user inputs
    if (inRef == "") {
      alert("A reference must be used to store a key");
      return;
    }
    if (inPubKey == "") {
      alert("A key must be inputted before it can be stored");
      return;
    }

    const response1 = await chrome.runtime.sendMessage({
      action: "getPKStorage",
    });
    if (response1.success) {
      const { keyRef, publicSKey } = response1;

      // check for duplicates
      if (publicSKey.includes(inPubKey)) {
        alert("This public key has already been added.");
        return;
      } else if (keyRef.includes(inRef)) {
        alert("This key reference has already been used.");
        return;
      }
    }

    //send request to background
    const response = await chrome.runtime.sendMessage({
      action: "addPKStorage",
      payload: { ref: inRef, pubKey: inPubKey },
    });

    if (response.success) {
      //if return is successful, update table view with new data
      getPubKeyTable();
      return true;
    } else {
      console.log("Error - reply from adding to pkStorage table");
    }
  } catch (error) {
    console.log("error in setPubKeyTable:", error);
    return { success: false };
  }
}

async function copyPKey() {
  //check if a row is selected
  if (selPKKeyIndex == null) {
    console.log("No row selected");
    return;
  }

  try {
    const response = await chrome.runtime.sendMessage({
      action: "getPKStorage",
    });

    if (response.success) {
      const { keyRef, publicSKey } = response;

      // if isPublic is true then use pubK array, if false use privK array
      const keyToCopy = publicSKey[selPKKeyIndex];

      // write to clipboard
      await navigator.clipboard.writeText(keyToCopy);
      
    } else {
      console.log("Error getting PK storage for copying");
    }
  } catch (error) {
    console.error("Error copying PK key: ", error);
    return { success: false };
  }
}

async function delPKey() {
  //check if a row is selected
  if (selPKKeyIndex == null) {
    console.log("No row selected");
    return;
  }

  try {
    const response = await chrome.runtime.sendMessage({
      action: "getPKStorage",
    });

    if (response.success) {
      const { keyRef, publicSKey } = response;

      // delete the selected row from the array
      keyRef.splice(selPKKeyIndex, 1);
      publicSKey.splice(selPKKeyIndex, 1);

      // send the updated arrays back to storage
      await chrome.runtime.sendMessage({
        action: "setKeySData",
        payload: { keyRef, publicSKey },
      });

      // reset selected row
      selPKKeyIndex = null;

      // update the visable table
      getPubKeyTable();

    } else {
      console.log("Error getting PK keys to delete");
    }
  } catch (error) {
    console.log("Error deleting PK key row: ", error);
    return { success: false };
  }
}

async function wipeAllData() {
  // get user confirmation before wiping all data
  if (!confirm("This action deletes all stored data and is unrecoverable")) {
    return;
  }
  try {
    const response = await chrome.runtime.sendMessage({
      action: "wipeAllData",
    });

    if (response.success) {
      document.getElementById("storageTable").innerHTML = "";
      document.getElementById("pkTable").innerHTML = "";
    }

  } catch (error) {
    console.log("Error wiping all stored data: ", error);
    return { success: false };
  }
}

//logo btn swap face
let face = 0;
async function swapLogo() {
  // face = 0  <- logo
  // face = 1  <- text
  const logo = document.getElementById("logoImg");
  const text = document.getElementById("logoTxt");

  if (face == 0) {
    face += 1;
    logo.style.display = "none";
    text.style.display = "flex";
  } else {
    face -= 1;
    logo.style.display = "flex";
    text.style.display = "none";
  }
}

// -------------------------------------- Button Listeners --------------------------------------

// Wait for DOM to load before attaching event listeners
document.addEventListener("DOMContentLoaded", () => {

  //load only the main page first
  swapPage(0);

  const genKeysBtn = document.getElementById("genKeysBtn");
  // for key generation button
  if (genKeysBtn) {
    genKeysBtn.addEventListener("click", getNewKeyPair);
    //console.log("Key generation button listener attached");
  } else {
    console.error("genKeysBtn not found in DOM");
  }

  const resetNumsBtn = document.getElementById("resetNumsBtn");
  if (resetNumsBtn) {
    resetNumsBtn.addEventListener("click", resetKGStorage);
    //console.log("storage reset");
  } else {
    console.error("reset button not found");
  }

  const copyPubKGBtn = document.getElementById("copyPubKGBtn");
  if (copyPubKGBtn) {
    copyPubKGBtn.addEventListener("click", () => copyKGKey(true));
    //console.log("copy KG pub btn");
  } else {
    console.log("copyKGpub button not found");
  }

  const copyPrivKGBtn = document.getElementById("copyPrivKGBtn");
  if (copyPrivKGBtn) {
    copyPrivKGBtn.addEventListener("click", () => copyKGKey(false));
    //console.log("copy KG priv btn");
  } else {
    console.log("copyKGpriv button not found");
  }

  const delKGRowBtn = document.getElementById("deleteKGBtn");
  if (delKGRowBtn) {
    delKGRowBtn.addEventListener("click", delKGKey);
    //console.log("delKGRow btn");
  } else {
    console.log("delKGRow btn not found");
  }

  const encryptBtn = document.getElementById("encBtn");
  if (encryptBtn) {
    encryptBtn.addEventListener("click", encryptFromButton);
    //console.log("Encrypt button");
  } else {
    console.error("encrypt button not found");
  }

  const decBtn = document.getElementById("decBtn");
  if (decBtn) {
    decBtn.addEventListener("click", decryptFromButton);
    //console.log("Decrypt btn");
  } else {
    console.log("decBtn not found");
  }

  const copyBtn = document.getElementById("cpyClip");
  var txtData = document.getElementById("outData");
  if (copyBtn) {
    copyBtn.addEventListener("click", async () => {
      try {
        await navigator.clipboard.writeText(txtData.value);
        //console.log("Written to clipboard");
      } catch (error) {
        console.log("Error copying to clipboard:", error);
      }
    });
  }

  const wipeBtn = document.getElementById("dataWipeBtn");
  if (wipeBtn) {
    wipeBtn.addEventListener("click", wipeAllData);
    //console.log("Wipe btn");
  } else {
    console.log("Wipe bttn not found");
  }

  const refPubSetBtn = document.getElementById("pkInBtn");
  if (refPubSetBtn) {
    refPubSetBtn.addEventListener("click", async () => {
      const success = await setPubKeyTable();
      if (success) {
        // clears the inputted values from the input boxes
        document.getElementById("refIn").value = "";
        document.getElementById("pkIn").value = "";
      }
    });
  } else {
    console.log("refPub btn not found");
  }

  const pkCopyBtn = document.getElementById("pkCopyBtn");
  if (pkCopyBtn) {
    pkCopyBtn.addEventListener("click", copyPKey);
    //console.log("PK copy btn");
  } else {
    console.log("pk copy btn not found");
  }

  const pkDelBtn = document.getElementById("pkDelBtn");
  if (pkDelBtn) {
    pkDelBtn.addEventListener("click", delPKey);
    //console.log("PK del btn");
  } else {
    console.log("pk del btn not found");
  }

  // for logo button
  const logoImgBtn = document.getElementById("logoImg");
  if (logoImgBtn) {
    logoImgBtn.addEventListener("click", swapLogo);
    //console.log("logoBtn");
  } else {
    console.log("logoBtn not found");
  }
  // for logo text
  const logoTxtBtn = document.getElementById("logoTxt");
  if (logoTxtBtn) {
    logoTxtBtn.addEventListener("click", swapLogo);
    //console.log("logotxtBtn");
  } else {
    console.log("logotxtBtn not found");
  }

  // ------------ for nav bar swapping ---------------------
  const mainBtn = document.getElementById("mainBtn");
  if (mainBtn) {
    mainBtn.addEventListener("click", () => swapPage(0));
    //console.log("Nav bttn 0");
  } else {
    console.error("nav bttn 0 not found");
  }

  const storBtn = document.getElementById("storBtn");
  if (storBtn) {
    storBtn.addEventListener("click", () => swapPage(1));
    //console.log("Nav bttn 1");
  } else {
    console.error("nav bttn 1 not found");
  }

  const keyBtn = document.getElementById("keyBtn");
  if (keyBtn) {
    keyBtn.addEventListener("click", () => swapPage(2));
    //console.log("Nav bttn 2");
  } else {
    console.error("nav bttn 2 not found");
  }

  const faqBtn = document.getElementById("faqBtn");
  if (faqBtn) {
    faqBtn.addEventListener("click", () => swapPage(3));
    //console.log("Nav bttn 3");
  } else {
    console.error("nav bttn 3 not found");
  }
  //----------------------------------------------------------

});