from abc import ABCMeta, abstractmethod
from typing import Type, Union, Optional, cast
import json
import base64
from cryptography import x509
import cryptography.hazmat.primitives.serialization as serial
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from jose import jwk
from jose.backends.cryptography_backend import CryptographyRSAKey
from getpass import getpass
import requests

from .log import LoggerBase
from .typing import JsonValue, JsonDict, JsonList

RSAKey = cast(Type[CryptographyRSAKey], jwk.RSAKey)
Entity = Union[bytes, str, JsonDict]

class ACMEConfig(metaclass=ABCMeta):
  @property
  @abstractmethod
  def accountKey(self) -> str: pass
  
  @property
  @abstractmethod
  def newNonce(self) -> str: pass
  
  @property
  @abstractmethod
  def newAccount(self) -> str: pass
  
  @property
  @abstractmethod
  def newOrder(self) -> str: pass

class ACMEError(Exception):
  def __init__(self, url: str, status: int, details: JsonDict):
    self.url = url
    self.status = status
    self.details = details
  
  def __str__(self):
    details = json.dumps(self.details)
    return "error during ACME operation {}, status={}, details={}".format(
      self.url, self.status, details)

class ACMEClient:
  def __init__(self, config: ACMEConfig, logger: LoggerBase):
    self.config   = config
    self.keyAlg   = 'RS256'
    self.hashAlg  = hashes.SHA256
    self.padAlg   = padding.PKCS1v15
    self.keyID    = None
    self.logger   = logger
    
    self.loadKey(config.accountKey)

  def loadKey(self, path: str):
    with open(path, 'rb') as fin:
      self.logger("load account key path={}", path)
      keyRaw = fin.read()
    try:
      key = serial.load_ssh_private_key(keyRaw, None)
    except ValueError:
      secret = getpass(prompt="Enter passphrase for key '{}': ".format(path))
      key = serial.load_ssh_private_key(keyRaw, secret.encode())
    if not isinstance(key, rsa.RSAPrivateKey):
      raise ValueError("Only RSAPrivateKey is supported, got {}".format(type(key)))
    self.keyPriv = key
    self.keyPub  = key.public_key()
    keyJWK = cast(JsonDict, RSAKey(self.keyPub, self.keyAlg).to_dict())
    if 'alg' in keyJWK:
      del keyJWK['alg']
    self.keyJWK = keyJWK
    self.keyPrint = self.sha256(self.keyJWK)
    self.logger("keyPrint={}", self.keyPrint)
  
  def toJSON(self, x: JsonDict):
    return json.dumps(x, separators=(",", ":"), sort_keys=True).encode()
  
  def toBytes(self, x: Entity):
    if isinstance(x, str):
      x = x.encode()
    elif isinstance(x, dict):
      x = self.toJSON(x)
    return x
  
  def sha256(self, x: Entity):
    digest = hashes.Hash(hashes.SHA256())
    digest.update(self.toBytes(x))
    return self.urlbase64(digest.finalize())

  def urlbase64(self, x: Entity):
    return base64.urlsafe_b64encode(self.toBytes(x)).decode().replace('=', '')
  
  def getNonce(self):
    resp = requests.head(self.config.newNonce)
    return resp.headers['Replay-Nonce']
  
  def sign(self, url: str, payload: Optional[JsonDict]) -> JsonDict:
    nonce = self.getNonce()
    header: JsonDict = { 'alg': self.keyAlg, 'nonce': nonce, 'url': url }
    if self.keyID is not None:
      header['kid'] = self.keyID
    else:
      header['jwk'] = self.keyJWK
    headerEnc = self.urlbase64(header)
    if payload is None:
      payloadEnc = ""
    else:
      payloadEnc = self.urlbase64(payload)
    unsigned = '.'.join([headerEnc, payloadEnc]).encode()
    signature = self.keyPriv.sign(unsigned, self.padAlg(), self.hashAlg())
    signature = self.urlbase64(signature)
    return { 'protected': headerEnc, 'payload': payloadEnc, 'signature': signature }
  
  def signAndSend(self, url: str, payload: Optional[JsonDict]):
    req = self.sign(url, payload)
    req = self.toJSON(req)
    self.logger("ACME request url={}", url)
    resp = requests.post(url, data=req, headers={ 'Content-Type': 'application/jose+json' })
    if resp.status_code != 200 and resp.status_code != 201:
      raise ACMEError(url, resp.status_code, resp.json())
    self.logger("response location={}", resp.headers.get('Location'))
    return resp
  
  def register(self, mail: Optional[str]=None):
    payload: JsonDict = { 'termsOfServiceAgreed': True }
    if mail is not None:
      payload['contact'] = [ "mailto: {}".format(mail) ]
    resp = self.signAndSend(self.config.newAccount, payload)
    self.keyID = resp.headers['Location']
    self.logger("register successful KID={}", self.keyID)

  def newOrder(self, domain: str):
    self.logger("newOrder domain={}", domain)
    payload: JsonDict = { 'identifiers': [{ 'type': 'dns', 'value': domain }] }
    resp = self.signAndSend(self.config.newOrder, payload)
    return resp.headers['Location'], resp.json()
  
  def getAsPost(self, url: str, text: bool=False) -> JsonValue:
    self.logger("get as post request location={}", url)
    resp = self.signAndSend(url, None)
    if text:
      return resp.text
    else:
      return resp.json()
  
  def getChallenge(self, authURL: str):
    auth = cast(JsonDict, self.getAsPost(authURL))
    challenge = None
    for item in cast(JsonList, auth['challenges']):
      chall = cast(JsonDict, item)
      if chall['type'] == 'dns-01':
        challenge = chall
        break
    if challenge is None:
      raise RuntimeError("No valid challenge found auth={}".format(authURL))
    
    id = cast(JsonDict, auth['identifier'])
    domain = cast(str, id['value'])
    domain = "_acme-challenge." + domain
    
    token = cast(str, challenge['token'])
    authVal = '.'.join([token, self.keyPrint])
    return cast(str, challenge['url']), domain, self.sha256(authVal)
  
  def finalize(self, finalURL: str, csr: x509.CertificateSigningRequest):
    csrEnc = self.urlbase64(csr.public_bytes(serial.Encoding.DER))
    self.signAndSend(finalURL, { 'csr': csrEnc })