const Parse = require("parse/node").Parse;
const httpsRequest = require("./httpsRequest");
const NodeRSA = require("node-rsa");
const jwt = require("jsonwebtoken");
const admin = require("firebase-admin");

// This adapter, modified from the 'apple' one in parse-server, validates a user when
// presented with a valid, current firebase-auth token from the appropriate domain whose email
// matches the desired parse-server ID.
// Enhance: if we come to support more than one app from this domain, we may need to
// check that the authorization is specific to Bloom. I think the 'audience' field
// in the token may become relevant.
// Enhance: if we support Bloom Library users changing their email, we need some
// way to keep track of the original email which is their parse-server ID,
// or some way to change that.

// A URL where we can get the current list of public keys that match the ones firebase
// uses to encrypt tokens. See getPublicKeys().
const TOKEN_ISSUER =
    "https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com";

let currentKey;

const getPublicKeys = async () => {
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
    // data we get from firebase api looks like an object with three keys; the values are the possible public key strings.
    // I don't know what the keys are, but we just need the values. Currently (7 Feb 2020) the third key is the one
    // that actually works on the login I tested, but other cases (perhaps other providers) may use the others,
    // or the number of keys may even change.
    return Object.values(data);
};

const tryPublicKeys = (token, publicKeys) => {
    // publicKeys is expected to be an array (from Object.values()), but for some reason
    // it doesn't have a foreach function, so using the old loop approach.
    for (var i = 0; i < publicKeys.length; i++) {
        const publicKey = publicKeys[i];
        try {
            // This checks that the token is actually the standard encoding of a Java Web Token
            // and encypted with the given private key and returns it decoded.
            // It will fail appropriately if the token is expired.
            const jwtClaims = jwt.verify(token, publicKey, {
                algorithms: "RS256"
            });
            if (jwtClaims) {
                return jwtClaims;
            }
        } catch (error) {
            // Very commonly the first couple of private keys fail, we don't need to clutter the log.
            //console.log(error);
        }
    }
    return null;
};

const verifyIdToken = async ({ token, id }, clientID) => {
    if (!token) {
        throw new Parse.Error(
            Parse.Error.OBJECT_NOT_FOUND,
            "id token is invalid for this user."
        );
    }

    const publicKeys = await getPublicKeys();
    //console.log("getPublicKeys returned " + JSON.stringify(publicKeys));

    const jwtClaims = tryPublicKeys(token, publicKeys);
    if (!jwtClaims) {
        throw new Parse.Error(
            Parse.Error.OBJECT_NOT_FOUND,
            `No public key could verify the token`
        );
    }

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
