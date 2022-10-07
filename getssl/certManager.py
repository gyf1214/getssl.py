import os
from datetime import datetime
from typing import Type
from enum import Enum
from abc import ABCMeta, abstractmethod
from cryptography import x509
import cryptography.hazmat.primitives.serialization as serial
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import hashes
from contextlib import contextmanager
from getpass import getpass

from .log import LoggerBase
from .typing import PrivateKeyTypes

class KeyType(Enum):
  RSA = 'rsa'
  EC = 'ec'
  
  def getKey(self, keySize: int=...) -> PrivateKeyTypes:
    defaultKeySize = { KeyType.RSA: 4096, KeyType.EC: 384 }
    # use NISP curves for compatibility reason
    curves: dict[int, Type[ec.EllipticCurve]] = {
      256: ec.SECP256R1, 384: ec.SECP384R1, 521: ec.SECP521R1
    }
    if keySize is Ellipsis:
      keySize = defaultKeySize[self]
    if self is KeyType.RSA:
      return rsa.generate_private_key(65537, keySize)
    else:
      curve = curves[keySize]
      return ec.generate_private_key(curve())
    
  @staticmethod
  def getType(key: PrivateKeyTypes):
    if isinstance(key, rsa.RSAPrivateKey):
      return KeyType.RSA
    else:
      return KeyType.EC

class CertManagerConfig(metaclass=ABCMeta):
  @property
  @abstractmethod
  def wd(self) -> str: pass

class CertManager(object):
  def __init__(self, config: CertManagerConfig, logger: LoggerBase):
    self.config = config
    self.logger = logger
  
  @property
  def domain(self): return self._domain

  @domain.setter
  def domain(self, value: str):
    self._domain = value
    self.baseName = datetime.now().strftime('%Y-%m-%d')
    if value.startswith('*.'):
      self.basePath = os.path.join(self.config.wd, 'wildcard', value[2:], self.baseName)
    else:
      self.basePath = os.path.join(self.config.wd, value, self.baseName)
    if not os.path.exists(self.basePath):
      os.makedirs(self.basePath, 0o700)
    self.logger("basepath set to {}", self.basePath)
  
  def getCSR(self, keyType: KeyType, keySize: int=...):
    self.logger("generate CSR domain={}, keySize={}", self._domain, keySize)
    builder = x509.CertificateSigningRequestBuilder()
    builder = builder.subject_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, self._domain)]))
    builder = builder.add_extension(x509.BasicConstraints(False, None), True)
    priv = keyType.getKey(keySize)
    return priv, builder.sign(priv, hashes.SHA256())

  @contextmanager
  def openForSafeWrite(self, path: str, binary: bool=True):
    try:
      fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
      mode = 'w'
      if binary:
        mode = mode + 'b'
      fp = open(fd, mode)
      yield fp
    finally:
      fp.close()
  
  def savePriv(self, priv: PrivateKeyTypes):
    typeName = KeyType.getType(priv).value
    privPath = os.path.join(self.basePath, '{}-{}'.format(typeName, self.baseName))
    with self.openForSafeWrite(privPath) as fout:
      secret = getpass(prompt="Enter passphrase for key '{}': ".format(privPath)).encode()
      encrypt = serial.BestAvailableEncryption(secret)
      privEnc = priv.private_bytes(serial.Encoding.PEM, serial.PrivateFormat.TraditionalOpenSSL, encrypt)
      fout.write(privEnc)
    self.logger("save privKey path={}", privPath)
  
  def saveCSR(self, csr: x509.CertificateSigningRequest, keyType: KeyType):
    csrPath = os.path.join(self.basePath, '{}-{}.csr'.format(keyType.value, self.baseName))
    with self.openForSafeWrite(csrPath) as fout:
      csrEnc = csr.public_bytes(serial.Encoding.PEM)
      fout.write(csrEnc)
    self.logger("save CSR path={}", csrPath)
  
  def saveCert(self, cert: str, keyType: KeyType):
    certPath = os.path.join(self.basePath, '{}-{}.ca_bundle'.format(keyType.value, self.baseName))
    with self.openForSafeWrite(certPath) as fout:
      certEnc = cert.encode()
      fout.write(certEnc)
    self.logger("save ca_bundle path={}", certPath)
