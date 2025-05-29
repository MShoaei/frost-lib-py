from frost_core import ed25519 as ed25519_r  # type: ignore
from frost_core import secp256k1 as secp256k1_r  # type: ignore
from frost_core import secp256k1_tr as secp256k1_tr_r  # type: ignore

from .abstracts import BaseCurveWithTweakedPubkey, BaseCurveWithTweakedSign


class Ed25519(BaseCurveWithTweakedPubkey):
    def _get_curve(self):
        return ed25519_r


class Secp256k1(BaseCurveWithTweakedPubkey):
    def _get_curve(self):
        return secp256k1_r


class Secp256k1Tr(BaseCurveWithTweakedSign):
    def _get_curve(self):
        return secp256k1_tr_r


ed25519 = Ed25519()
secp256k1 = Secp256k1()
secp256k1_tr = Secp256k1Tr()
