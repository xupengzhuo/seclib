from datetime import datetime, timedelta
import cryptography.x509.name
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat._oid import ObjectIdentifier
from cryptography import x509
from cryptography.exceptions import InvalidKey, InvalidSignature
from typing import Any

cryptography.x509.name._NAMEOID_TO_NAME.update(
    {
        x509.NameOID.SERIAL_NUMBER: "serialNumber",
        x509.NameOID.DN_QUALIFIER: "dnQualifier",
    }
)

# cryptography/x509/oid.py
# cryptography/x509/name.py
_nameoid_map: dict[str, ObjectIdentifier] = {
    "serialNumber": x509.NameOID.SERIAL_NUMBER,
    "C": x509.NameOID.COUNTRY_NAME,
    "countryName": x509.NameOID.COUNTRY_NAME,
    "CN": x509.NameOID.COMMON_NAME,
    "commonName": x509.NameOID.COMMON_NAME,
    "L": x509.NameOID.LOCALITY_NAME,
    "localityName": x509.NameOID.LOCALITY_NAME,
    "ST": x509.NameOID.STATE_OR_PROVINCE_NAME,
    "stateOrProvinceName": x509.NameOID.STATE_OR_PROVINCE_NAME,
    "O": x509.NameOID.ORGANIZATION_NAME,
    "organizationName": x509.NameOID.ORGANIZATION_NAME,
    "OU": x509.NameOID.ORGANIZATIONAL_UNIT_NAME,
    "organizationalUnitName": x509.NameOID.ORGANIZATIONAL_UNIT_NAME,
    "STREET": x509.NameOID.STREET_ADDRESS,
    "streetAddress": x509.NameOID.STREET_ADDRESS,
    "DC": x509.NameOID.DOMAIN_COMPONENT,
    "domainComponent": x509.NameOID.DOMAIN_COMPONENT,
    "UID": x509.NameOID.USER_ID,
    "userID": x509.NameOID.USER_ID,
    "DNQ": x509.NameOID.DN_QUALIFIER,
    "dnQualifier": x509.NameOID.DN_QUALIFIER,
    "MAIL": x509.NameOID.EMAIL_ADDRESS,
    "emailAddress": x509.NameOID.EMAIL_ADDRESS,
}


def _rsa_gen_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=4096)


def _parse_nameobj_to_dict(nameobj: x509.Name) -> dict[str, str]:
    _info = {}
    for n in nameobj:
        _k, _v = n.rfc4514_string().split("=", 1)
        _info[_k] = _v

    return _info


def _parse_dict_to_nameobj(name_info: dict[str, str]) -> x509.Name:
    return x509.Name(
        [x509.NameAttribute(_nameoid_map[k], v) for k, v in name_info.items()]
    )


class x509csr:
    csr: x509.CertificateSigningRequest | None
    public_key: Any
    private_key: Any
    _subject_info: dict[str, str] = {}

    def __init__(
        self,
        csr: bytes = None,
        pkey: bytes = None,
        pkeypasswd: bytes = None,
        subject_info: dict[str, str] = {},
    ) -> None:
        if csr:
            self.csr = x509.load_pem_x509_csr(csr)
            self.public_key = self.csr.public_key()
        else:
            self._subject_info = subject_info
            if pkey:
                self.private_key = serialization.load_pem_private_key(pkey, pkeypasswd)
            else:
                self.private_key = _rsa_gen_key()
            self.public_key = self.private_key.public_key()
            self.csr = None

    def read_subject_info(self) -> dict[str, str]:
        if self._subject_info:
            return self._subject_info

        if self.csr:
            self._subject_info = _parse_nameobj_to_dict(self.csr.subject)
        return self._subject_info

    def make(self) -> None:
        if self.csr:
            return

        csr_builder = x509.CertificateSigningRequestBuilder()
        csr_builder = csr_builder.subject_name(
            _parse_dict_to_nameobj(self._subject_info)
        )

        csr_builder = csr_builder.add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )

        self.csr = csr_builder.sign(self.private_key, hashes.SHA256())

    def dump(self, options) -> bytes | None:
        if options == "privatekey":
            if self.private_key:
                return self.private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                )
        elif options == "publickey":
            return self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        elif options == "signingrequest":
            if self.csr:
                return self.csr.public_bytes(serialization.Encoding.PEM)
        return None


class x509cert:
    nva: datetime
    nvb: datetime
    issuer_info: dict[str, str]
    subject_info: dict[str, str]
    public_key: Any
    private_key: Any
    cert: x509.Certificate | None
    level: str | None
    subca: int = 0
    serial_number: int = 0

    def __init__(
        self,
        pkey: bytes = None,
        pubk: bytes = None,
        cert: bytes = None,
        pkeypasswd: bytes = None,
        level: str = None,
        issuer_info: dict[str, str] = None,
        subject_info: dict[str, str] = None,
        daterange: tuple[datetime, datetime] = None,
        serial_number=None,
    ) -> None:

        if cert:
            self.cert = x509.load_pem_x509_certificate(cert)
            self.public_key = self.cert.public_key()
            self.nvb, self.nva = self.cert.not_valid_before, self.cert.not_valid_after
        else:
            if pkey:
                self.private_key = serialization.load_pem_private_key(pkey, pkeypasswd)
            elif pubk:
                self.private_key = None
                self.public_key = serialization.load_pem_public_key(pubk)
            else:
                self.private_key = _rsa_gen_key()
                self.public_key = self.private_key.public_key()

            self.subject_info = subject_info or {}
            self.level = level
            self.issuer_info = issuer_info or {}
            if daterange:
                self.nvb, self.nva = daterange
            if serial_number:
                self.serial_number = serial_number

    def read_subject_info(self) -> dict[str, str] | None:
        if not self.cert:
            return None
        return _parse_nameobj_to_dict(self.cert.subject)

    def read_issuer_info(self) -> dict[str, str] | None:
        if not self.cert:
            return None
        return _parse_nameobj_to_dict(self.cert.issuer)

    def read_nva(self) -> datetime | None:
        if not self.cert:
            return None

        return self.nva

    def read_nvb(self) -> datetime | None:
        if not self.cert:
            return None

        return self.nvb

    def read_version(self) -> x509.Version | None:
        if not self.cert:
            return None

        return self.cert.version

    def read_serial_number(self) -> int | None:
        if not self.cert:
            return None

        return self.cert.serial_number

    def read_fingerprint(self) -> str | None:
        if not self.cert:
            return None

        return self.cert.fingerprint(hashes.SHA256()).hex()

    def read_signature_hash_algorithm(self) -> hashes.HashAlgorithm | None:
        if not self.cert:
            return None

        return self.cert.signature_hash_algorithm

    def read_extensions(self) -> list[x509.ExtensionType] | None:
        if not self.cert:
            return None

        return [e.value for e in self.cert.extensions]

    def read_signature(self) -> bytes | None:
        if not self.cert:
            return None

        return self.cert.signature

    def read_tbs_certificate_bytes(self) -> bytes | None:
        if not self.cert:
            return None

        return self.cert.tbs_certificate_bytes

    def dump(self, options: str) -> bytes | None:
        if options == "privatekey":
            if self.private_key:
                return self.private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                )
        elif options == "publickey":
            return self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        elif options == "certificate":
            if self.cert:
                return self.cert.public_bytes(serialization.Encoding.PEM)
        return None

    def make(self, signer=None) -> None:
        if not signer:
            signer = self

        cert_builder = x509.CertificateBuilder()
        cert_builder = cert_builder.public_key(self.public_key)
        cert_builder = cert_builder.subject_name(
            _parse_dict_to_nameobj(self.subject_info)
        )
        cert_builder = cert_builder.issuer_name(
            _parse_dict_to_nameobj(self.issuer_info)
        )
        cert_builder = cert_builder.not_valid_before(self.nvb)
        cert_builder = cert_builder.not_valid_after(self.nva)
        cert_builder = cert_builder.serial_number(
            self.serial_number or x509.random_serial_number()
        )

        if self.level == "root":
            cert_builder = cert_builder.add_extension(
                x509.BasicConstraints(ca=True, path_length=None),
                critical=True,
            )
        elif self.level == "inter":
            cert_builder = cert_builder.add_extension(
                x509.BasicConstraints(ca=True, path_length=self.subca),
                critical=True,
            )
        elif self.level == "end":
            cert_builder = cert_builder.add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            )

        self.cert = cert_builder.sign(signer.private_key, hashes.SHA256())


def create_self_signed_cert(
    subject: dict[str, str], daterange: tuple[datetime, datetime]
) -> x509cert:
    cert = x509cert(
        None,
        level="root",
        issuer_info=subject,
        subject_info=subject,
        daterange=daterange,
    )
    cert.make()

    return cert


def create_signed_cert(
    signer_pkey: bytes,
    level: str,
    issuer: dict[str, str],
    subject: dict[str, str],
    daterange: tuple[datetime, datetime],
) -> x509cert:
    signer = x509cert(signer_pkey)

    crt = x509cert(
        None,
        level=level,
        issuer_info=issuer,
        subject_info=subject,
        daterange=daterange,
    )
    crt.make(signer)

    return crt


def create_signed_cert_by_csr(
    signer_pkey: bytes,
    csr: x509csr,
    level: str,
    issuer: dict[str, str],
    daterange: tuple[datetime, datetime],
) -> x509cert:
    signer = x509cert(signer_pkey)

    crt = x509cert(
        None,
        csr.dump("publickey"),
        None,
        level=level,
        issuer_info=issuer,
        subject_info=csr.read_subject_info(),
        daterange=daterange,
    )

    crt.make(signer)
    return crt


def load_cert(cert: bytes) -> x509cert:
    return x509cert(cert=cert)


def rsa_verify(issuer_cert: bytes, subject_cert: bytes) -> bool:
    crt = x509cert(cert=issuer_cert)
    crt_check = x509cert(cert=subject_cert)

    try:
        crt.public_key.verify(
            crt_check.read_signature(),
            crt_check.read_tbs_certificate_bytes(),
            padding.PKCS1v15(),
            crt_check.read_signature_hash_algorithm(),
        )
        return True
    except InvalidSignature:
        return False


def rsa_sign(cert: x509cert, plaintext: bytes) -> bytes:
    return cert.private_key.sign(plaintext, padding.PKCS1v15(), hashes.SHA256())


def rsa_encrypt(cert: x509cert, plaintext: bytes) -> bytes:
    return cert.public_key.encrypt(plaintext, padding.PKCS1v15())


def create_csr(
    subject_info: dict[str, str], pkey: bytes = None, pkeypasswd: bytes = None
) -> x509csr:
    csr = x509csr(subject_info=subject_info, pkey=pkey, pkeypasswd=pkeypasswd)
    csr.make()
    return csr
