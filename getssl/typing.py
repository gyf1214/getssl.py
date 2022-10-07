from typing import Union, List, Dict
from cryptography.hazmat.primitives.asymmetric import rsa, ec

JsonPrim = Union[str, int]
JsonDict = Dict[str, 'JsonValue']
JsonList = List['JsonValue']
JsonValue = Union[JsonPrim, JsonList, JsonDict]
PrivateKeyTypes = Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey]
PublicKeyTypes = Union[rsa.RSAPublicKey, ec.EllipticCurvePublicKey]
