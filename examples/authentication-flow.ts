import createWebAuth from "@sourceregistry/node-webauthn/server";
import {generateKeyPairSync} from "node:crypto";

const {privateKey, publicKey} = generateKeyPairSync("ec", {namedCurve: "P-256"});

const webauth = createWebAuth({
    keyPair: {
        kid: "main",
        private_key: privateKey,
        public_key: publicKey
    },
    issuer: "https://auth.example.com"
});

type StoredCredential = {
    credential_id: string;
    public_key: string;
    counter: number;
};

type AuthenticationSession = {
    challenge: string;
    rp_id: string;
    origin: string;
    credential_id: string;
};

const credentials = new Map<string, StoredCredential>();
const authenticationSessions = new Map<string, AuthenticationSession>();

export const beginAuthentication = (userId: string) => {
    const stored = credentials.get(userId);
    if (!stored) {
        throw new Error("Passkey not found");
    }

    const challenge = webauth.generateChallenge();
    const rp_id = "example.com";
    const origin = "https://example.com";

    authenticationSessions.set(userId, {
        challenge,
        rp_id,
        origin,
        credential_id: stored.credential_id
    });

    return {
        token: webauth.signAuthentication({
            sub: userId,
            challenge,
            rp_id,
            origin,
            redirect_uri: "https://example.com/login",
            credential_id: stored.credential_id
        }),
        publicKey: webauth.createAuthenticationOptions({
            challenge,
            rpId: rp_id,
            allowCredentials: [
                {
                    id: stored.credential_id,
                    type: "public-key" as const,
                    transports: ["internal"]
                }
            ],
            userVerification: "preferred" as const
        })
    };
};

export const finishAuthentication = (
    userId: string,
    token: string,
    credential: {
        client_data_json: string;
        authenticator_data: string;
        signature: string;
    }
) => {
    const session = authenticationSessions.get(userId);
    const stored = credentials.get(userId);

    if (!session || !stored) {
        throw new Error("Authentication session not found");
    }

    const claims = webauth.verifyAuthentication(token);
    if (claims.sub !== userId) {
        throw new Error("Authentication token subject mismatch");
    }

    const result = webauth.verifyAuthenticationResponse({
        expected_challenge: session.challenge,
        client_data_json: credential.client_data_json,
        authenticator_data: credential.authenticator_data,
        signature: credential.signature,
        origin: session.origin,
        rp_id: session.rp_id,
        public_key: stored.public_key,
        previous_counter: stored.counter,
        require_user_verification: false
    });

    credentials.set(userId, {
        ...stored,
        counter: result.counter
    });

    authenticationSessions.delete(userId);

    return {
        user_id: userId,
        authenticated: true,
        user_verified: result.user_verified,
        counter: result.counter
    };
};
