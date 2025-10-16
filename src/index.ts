const passkey = {
    generate: () => {

    },
    verify: () => {

    }
}

export default passkey;

export const generate = passkey.generate.bind(passkey);
export const verify = passkey.verify.bind(passkey);



