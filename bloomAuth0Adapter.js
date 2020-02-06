const Parse = require("parse/node").Parse;
const httpsRequest = require("./httpsRequest");
const NodeRSA = require("node-rsa");
const jwt = require("jsonwebtoken");
const admin = require("firebase-admin");

// This adapter, modified from the 'apple' one in parse-server, validates a user when
// presented with a valid, current auth0 token from the appropriate domain whose email
// matches the desired parse-server ID.
// Enhance: if we come to support more than one app from this domain, we may need to
// check that the authorization is specific to Bloom. I think the 'audience' field
// in the token may become relevant.
// Enhance: if we support Bloom Library users changing their email, we need some
// way to keep track of the original email which is their parse-server ID,
// or some way to change that. One option is to have auth0 add a field which
// tracks the email under which the user originally signed up.

// For JohnT experimental domain; eventually need the LsDev one for production/development
// as appropriate.
// To find the key, go to https://experiment-bloomlibrary.auth0.com/.well-known/openid-configuration,
// and look for the issuer field. Probably always just our domain.
const TOKEN_ISSUER =
    "https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com";
// process.env.APP_ID === "R6qNTeumQXjJCMutAJYAwPtip1qBulkFyLefkCE5"
//     ? "https://languagetechnology.auth0.com/"
//     : process.env.APP_ID === "yrXftBF6mbAuVu3fO6LnhCJiHxZPIdE7gl1DUVGR"
//     ? "https://dev-sillsdev.auth0.com/"
//     : "https://experiment-bloomlibrary.auth0.com/";

let currentKey;

const getPublicKey = async () => {
    let data;
    try {
        // See https://auth0.com/docs/tokens/guides/jwt/use-jwks for the structure of this.
        data = await httpsRequest.get(TOKEN_ISSUER);
    } catch (e) {
        if (currentKey) {
            return currentKey;
        }
        console.log("failed to get public key token " + JSON.stringify(e));
        throw e;
    }

    console.log("getPublicKey got " + JSON.stringify(data));
    // Enhance: according to https://auth0.com/docs/tokens/guides/jwt/use-jwks, there could be
    // more than one public key. The article doesn't say what to do about it if so; my guess is
    // that the JWT is considered valid if any of the current signing keys decrypts it successfully.
    // It appears that this can only happen while we're in the process of changing public keys,
    // which there seems little reason to do, so this is probably very low priority.
    const key = data.keys[0];

    const pubKey = new NodeRSA();
    pubKey.importKey(
        { n: Buffer.from(key.n, "base64"), e: Buffer.from(key.e, "base64") },
        "components-public"
    );
    currentKey = pubKey.exportKey(["public"]);
    return currentKey;
};

let doneFirebaseInit = false;

const verifyIdToken = async ({ token, id }, clientID) => {
    if (!token) {
        throw new Parse.Error(
            Parse.Error.OBJECT_NOT_FOUND,
            "id token is invalid for this user."
        );
    }
    if (!doneFirebaseInit) {
        doneFirebaseInit = true;
        var serviceAccount = require("d:/sil-bloomlibrary-firebase-adminsdk-4cf0u-02622f06e4.json");

        admin.initializeApp({
            credential: admin.credential.cert(serviceAccount),
            databaseURL: "https://sil-bloomlibrary.firebaseio.com"
        });

        // admin.initializeApp({
        //     credential: admin.credential.applicationDefault(),
        //     databaseURL: "https://sil-bloomlibrary.firebaseio.com"
        // });
    }
    // idToken comes from the client app
    let jwtClaims = undefined;
    try {
        jwtClaims = await admin.auth().verifyIdToken(token);
    } catch (error) {
        console.log("firebaseadmin returned error " + JSON.stringify(error));
        throw new Parse.Error(
            Parse.Error.OBJECT_NOT_FOUND,
            `firebaseadmin could not verify this user ${id}.`
        );
    }
    console.log("firebaseadmin returned " + JSON.stringify(jwtClaims));
    // enhance: according to https://auth0.com/docs/tokens/guides/jwt/use-jwks, it is valid to cache the public key,
    // which rarely changes; but if validation fails the code ought to retrieve it afresh and re-check.
    //const publicKey = await getPublicKey();

    // This checks that the token is actually the standard encoding of a Java Web Token
    // and encypted with the appropriate private key and returns it decoded.
    // It will fail appropriately if the token is expired.
    // const jwtClaims = jwt.verify(token, publicKey, {
    //     algorithms: "RS256"
    // });

    // Make sure it was our server that issued the token!
    const tokenSource = "https://securetoken.google.com/sil-bloomlibrary";
    if (jwtClaims.iss !== tokenSource) {
        throw new Parse.Error(
            Parse.Error.OBJECT_NOT_FOUND,
            `id token not issued by correct OpenID provider - expected: ${tokenSource} actually from: ${jwtClaims.iss}`
        );
    }
    // And that it's a token validating the user we're trying to log in!
    // Enhance: this is where we might have to tweak things to support changing email.
    if (jwtClaims.email !== id) {
        throw new Parse.Error(
            Parse.Error.OBJECT_NOT_FOUND,
            `auth data ${jwtClaims.email} is invalid for this user ${id}.`
        );
    }
    // And that the email is verified. This is important so the ID of someone who
    // hasn't yet registered with auth0 can't be taken over by someone else.
    if (!jwtClaims.email_verified) {
        throw new Parse.Error(
            Parse.Error.OBJECT_NOT_FOUND,
            `auth data does not have verified email for this user ${id}.`
        );
    }
    // This code was present from the apple original. It's probably obsolete,
    // since I don't think the jwtClaims object we get has an aud property,
    // and therefore presume this test isn't being done because clientID is undefined.
    // if (clientID !== undefined && jwtClaims.aud !== clientID) {
    //     throw new Parse.Error(
    //         Parse.Error.OBJECT_NOT_FOUND,
    //         `jwt aud parameter does not include this client - is: ${jwtClaims.aud} | expected: ${clientID}`
    //     );
    // }
    return jwtClaims;
};

// Returns a promise that fulfills if this id token is valid
function validateAuthData(authData, options = {}) {
    // return Promise.resolve(); // allows anyone to log in, may be useful in debugging.
    //console.log("validating " + JSON.stringify(authData));
    return verifyIdToken(authData, options.client_id);
}

// Returns a promise that fulfills if this app id is valid.
// Seems to work fine to always fulfill; I don't really understand what this is for.
function validateAppId() {
    return Promise.resolve();
}

module.exports = {
    validateAppId,
    validateAuthData
};
