import pyotp
import qrcode

def generate_secret():

    return pyotp.random_base32()


def generate_code(
    secret,
):

    totp = pyotp.TOTP(
        secret
    )

    return totp.now()


def verify_code(
    secret,
    code,
):

    totp = pyotp.TOTP(
        secret
    )

    return totp.verify(
        code
    )
    
def generate_qr(
    email,
    secret,
):

    uri = pyotp.totp.TOTP(
        secret
    ).provisioning_uri(
        name=email,
        issuer_name="Chameleon"
    )

    qr = qrcode.make(uri)

    return qr