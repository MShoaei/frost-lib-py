from abc import ABC, abstractmethod

from pydantic import BaseModel

from .custom_types import (
    Commitment,
    DKGPart1Package,
    DKGPart1Result,
    DKGPart1Secret,
    DKGPart2Package,
    DKGPart2Result,
    DKGPart2Secret,
    DKGPart3Result,
    HexStr,
    KeyPair,
    Nonce,
    PrivateKeyPackage,
    PubkeyWithShare,
    PublicKeyPackage,
    Round1Sign,
    SecretShare,
    SharePackage,
    SigningPackage,
)


def model_to_dict(data: BaseModel):
    return data.model_dump(mode="python")


def nested_model_to_dict[T: BaseModel](data: dict[HexStr, T]):
    new_data = {}
    for key, value in data.items():
        new_data[key] = value.model_dump(mode="python")
    return new_data


class BaseCryptoCurve(ABC):
    def __init__(self):
        self._curve = self._get_curve()

    @property
    @abstractmethod
    def name(self):
        raise NotImplementedError()

    @abstractmethod
    def _get_curve(self):
        raise NotImplementedError()

    def keypair_new(self) -> KeyPair:
        return KeyPair.model_validate(self._curve.keypair_new())

    def single_sign(self, secret: HexStr, msg: bytes) -> HexStr:
        return self._curve.single_sign(secret, msg)

    def single_verify(self, signature: HexStr, msg: bytes, pubkey: HexStr) -> bool:
        return self._curve.single_verify(signature, msg, pubkey)

    def num_to_id(self, num: int) -> HexStr:
        return self._curve.num_to_id(num)

    def dkg_part1(self, identifier: HexStr, max_signers: int, min_signers: int) -> DKGPart1Result:
        return DKGPart1Result.model_validate(self._curve.dkg_part1(identifier, max_signers, min_signers))

    def dkg_part2(
        self,
        round1_secret_package: DKGPart1Secret,
        round1_packages: dict[HexStr, DKGPart1Package],
    ) -> DKGPart2Result:
        return DKGPart2Result.model_validate(
            self._curve.dkg_part2(
                model_to_dict(round1_secret_package),
                nested_model_to_dict(round1_packages),
            )
        )

    def dkg_verify_secret_share(self, identifier: HexStr, secret_share: SharePackage, commitment: Commitment) -> bool:
        return self._curve.dkg_verify_secret_share(identifier, secret_share, commitment)

    def dkg_part3(
        self,
        round2_secret_package: DKGPart2Secret,
        round1_packages: dict[HexStr, DKGPart1Package],
        round2_packages: dict[HexStr, DKGPart2Package],
    ) -> DKGPart3Result:
        return DKGPart3Result.model_validate(
            self._curve.dkg_part3(
                model_to_dict(round2_secret_package),
                nested_model_to_dict(round1_packages),
                nested_model_to_dict(round2_packages),
            )
        )

    def get_pubkey(self, secret: HexStr) -> HexStr:
        return self._curve.get_pubkey(secret)

    def key_package_from(self, key_share: SecretShare) -> PrivateKeyPackage:
        return PrivateKeyPackage.model_validate(self._curve.key_package_from(model_to_dict(key_share)))

    def round1_commit(self, key_share: HexStr) -> Round1Sign:
        return Round1Sign.model_validate(self._curve.round1_commit(key_share))

    def signing_package_new(self, signing_commitments: dict[HexStr, Commitment], msg: bytes) -> SigningPackage:
        return SigningPackage.model_validate(
            self._curve.signing_package_new(nested_model_to_dict(signing_commitments), msg)
        )

    def round2_sign(
        self,
        signing_package: SigningPackage,
        signer_nonces: Nonce,
        key_package: PrivateKeyPackage,
    ) -> SharePackage:
        return SharePackage.model_validate(
            self._curve.round2_sign(
                model_to_dict(signing_package),
                model_to_dict(signer_nonces),
                model_to_dict(key_package),
            )
        )

    def aggregate(
        self,
        signing_package: SigningPackage,
        signature_shares: dict[HexStr, SharePackage],
        pubkey_package: PublicKeyPackage,
    ) -> HexStr:
        return self._curve.aggregate(
            model_to_dict(signing_package),
            nested_model_to_dict(signature_shares),
            model_to_dict(pubkey_package),
        )

    def keys_generate_with_dealer(self, max_signers: int, min_signers: int) -> PubkeyWithShare:
        return PubkeyWithShare.model_validate(self._curve.keys_generate_with_dealer(max_signers, min_signers))

    def verify_group_signature(self, signature: HexStr, msg: bytes, pubkey_package: PublicKeyPackage) -> bool:
        return self._curve.verify_group_signature(signature, msg, model_to_dict(pubkey_package))

    def pubkey_package_tweak(
        self, pubkey_package: PublicKeyPackage, merkle_root: bytes | None = None
    ) -> PublicKeyPackage:
        return PublicKeyPackage.model_validate(
            self._curve.pubkey_package_tweak(model_to_dict(pubkey_package), merkle_root)
        )

    def key_package_tweak(self, key_package: PrivateKeyPackage, merkle_root: bytes | None = None) -> PrivateKeyPackage:
        return PrivateKeyPackage.model_validate(self._curve.key_package_tweak(model_to_dict(key_package), merkle_root))

    def keys_split(self, secret: HexStr, max_signers: int, min_signers: int) -> PubkeyWithShare:
        return PubkeyWithShare.model_validate(
            self._curve.keys_split(
                secret,
                max_signers,
                min_signers,
            )
        )


class BaseCurveWithTweakedPubkey(BaseCryptoCurve, ABC):
    def pubkey_tweak(self, verifying_key: HexStr, merkle_root: bytes | None = None) -> HexStr:
        return self._curve.pubkey_tweak(verifying_key, merkle_root)


class BaseCurveWithTweakedSign(BaseCryptoCurve, ABC):
    def round2_sign_with_tweak(
        self,
        signing_package: SigningPackage,
        signer_nonces: Nonce,
        key_package: PrivateKeyPackage,
        merkle_root: bytes | None = None,
    ) -> SharePackage:
        return SharePackage.model_validate(
            self._curve.round2_sign_with_tweak(
                model_to_dict(signing_package),
                model_to_dict(signer_nonces),
                model_to_dict(key_package),
                merkle_root,
            )
        )

    def aggregate_with_tweak(
        self,
        signing_package: SigningPackage,
        signature_shares: dict[HexStr, SharePackage],
        pubkey_package: PublicKeyPackage,
        merkle_root: bytes | None = None,
    ) -> HexStr:
        return self._curve.aggregate_with_tweak(
            model_to_dict(signing_package),
            nested_model_to_dict(signature_shares),
            model_to_dict(pubkey_package),
            merkle_root,
        )
