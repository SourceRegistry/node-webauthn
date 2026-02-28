import createWebAuthClient from "@sourceregistry/node-webauthn/client";

const client = createWebAuthClient();

type RegistrationStartResponse = {
    token: string;
    publicKey: Parameters<typeof client.startRegistration>[0];
};

type AuthenticationStartResponse = {
    token: string;
    publicKey: Parameters<typeof client.startAuthentication>[0];
};

export const registerPasskey = async (response: RegistrationStartResponse) => {
    const credential = await client.startRegistration(response.publicKey);

    await fetch("/api/webauth/register/finish", {
        method: "POST",
        headers: {"content-type": "application/json"},
        credentials: "include",
        body: JSON.stringify({
            token: response.token,
            credential
        })
    });
};

export const authenticatePasskey = async (response: AuthenticationStartResponse) => {
    const credential = await client.startAuthentication(response.publicKey);

    await fetch("/api/webauth/authenticate/finish", {
        method: "POST",
        headers: {"content-type": "application/json"},
        credentials: "include",
        body: JSON.stringify({
            token: response.token,
            credential
        })
    });
};
