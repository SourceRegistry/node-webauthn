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

type StoredRegistrationSession = {
    challenge: string;
    rp_id: string;
    origin: string;
};

const registrationSessions = new Map<string, StoredRegistrationSession>();

export const beginRegistration = (userId: string, email: string): {
    token: string;
    publicKey: ReturnType<typeof webauth.createRegistrationOptions>;
} => {
    const challenge = webauth.generateChallenge();
    const rp_id = "example.com";
    const origin = "https://example.com";

    registrationSessions.set(userId, {challenge, rp_id, origin});

    return {
        token: webauth.signRegistration({
            sub: userId,
            challenge,
            rp_id,
            origin,
            redirect_uri: "https://example.com/settings/passkeys"
        }),
        publicKey: webauth.createRegistrationOptions({
            challenge,
            rp: {
                name: "Example Inc.",
                id: rp_id
            },
            user: {
                id: webauth.toBase64Url(userId),
                name: email,
                displayName: email
            },
            authenticatorSelection: {
                residentKey: "preferred",
                userVerification: "preferred"
            }
        })
    };
};

export const finishRegistration = (
    userId: string,
    token: string,
    credential: {
        id: string;
        client_data_json: string;
        attestation_object: string;
        transports?: string[];
    }
) => {
    const session = registrationSessions.get(userId);
    if (!session) {
        throw new Error("Registration session not found");
    }

    const claims = webauth.verifyRegistration(token);
    if (claims.sub !== userId) {
        throw new Error("Registration token subject mismatch");
    }

    const parsed = webauth.parseRegistration({
        expected_challenge: session.challenge,
        credential_id: credential.id,
        client_data_json: credential.client_data_json,
        attestation_object: credential.attestation_object,
        transports: credential.transports ?? [],
        origin: session.origin,
        rp_id: session.rp_id
    });

    registrationSessions.delete(userId);

    return {
        user_id: userId,
        credential_id: parsed.credential_id,
        public_key: parsed.public_key,
        counter: parsed.counter,
        transports: parsed.transports,
        attestation_format: parsed.attestation_format
    };
};
