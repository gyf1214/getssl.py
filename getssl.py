import sys
import os
import time
from datetime import datetime
from typing import TextIO, Any, Optional, Union
from contextlib import contextmanager
from abc import ABCMeta, abstractmethod
import json
import base64
from cryptography import x509
import cryptography.hazmat.primitives.serialization as serial
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from jose import jwk
from getpass import getpass
import requests

class LoggerBase(metaclass=ABCMeta):
  @abstractmethod
  def __call__(self, fmt: str, *args: Any, **kwds: Any):
    pass

class DummyLogger(LoggerBase):
  def __call__(self, fmt: str, *args: Any, **kwds: Any):
    pass

class DebugLogger(LoggerBase):
  def __init__(self, debug: bool=False, fout: TextIO=sys.stderr):
    self.debug = debug
    self.fout = fout
  
  def __call__(self, fmt: str, *args: Any, **kwargs: Any):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")
    frame = sys._getframe(1)
    if self.debug and frame is not None:
      filename = os.path.basename(frame.f_code.co_filename)
      lineno = frame.f_lineno
      fmt = "[{}][{:>12}:{:<5}] {}".format(now, filename, lineno, fmt)
    else:
      fmt = "[{}] {}".format(now, fmt)
    output = fmt.format(*args, **kwargs)
    print(output, file=self.fout, flush=True)

class Config:
  def __init__(self, path: str, logger: LoggerBase):
    self.encoding   = 'utf-8'
    logger("read config path={}", path)
    with open(path, "r") as fin:
      raw = json.load(fin)
    self.wd = raw['workingDir']
    # CA
    self.ca         = raw['ca']
    allMethods      = requests.get(self.ca).json()
    self.newAccount = allMethods['newAccount']
    self.newNonce   = allMethods['newNonce']
    self.newOrder   = allMethods['newOrder']
    self.revokeCert = allMethods['revokeCert']
    self.accountKey = raw['accountKey']
    logger("CA url={}, accountKey={}", self.ca, self.accountKey)
    # dnspod
    self.dnspod       = raw['dnspod']
    self.recordList   = self.dnspod + '/Record.List'
    self.recordCreate = self.dnspod + '/Record.Create'
    self.recordDelete = self.dnspod + '/Record.Remove'
    self.dnspodToken  = raw['dnspodToken']
    self.baseDomain   = raw['baseDomain']
    logger("dnspod url={}, baseDomain={}", self.dnspod, self.baseDomain)

class DNSPodError(Exception):
  def __init__(self, url: str, status: int, retcode: int, message: str):
    self.url     = url
    self.status  = status
    self.retcode = retcode
    self.message = message
  
  def __str__(self):
    return "error during DNSPod operation {}, status={}, retcode={}, message={}".format(
      self.url, self.status, self.retcode, self.message)

class DNSPodClient:
  def __init__(self, config: Config, logger: LoggerBase):
    self.config = config
    self.logger = logger
    self.token  = config.dnspodToken
    self.domain = config.baseDomain
  
  def send(self, url: str, data: dict={}):
    x = { 'domain': self.domain, 'login_token': self.token, 'format': 'json', 'lang': 'en' }
    x.update(data)
    self.logger("DNSPod request url={}", url)
    resp = requests.post(url, x)
    ret = resp.json()
    retStatus = ret['status']
    if resp.status_code != 200 or retStatus['code'] != '1':
      raise DNSPodError(url, resp.status_code, int(retStatus['code']), retStatus['message'])
    return ret
  
  def recordFromDomain(self, domain: str):
    suffix = '.' + self.domain
    if domain.endswith(suffix):
      domain = domain[:-len(suffix)]
    return domain
  
  def listRecord(self):
    ret = self.send(self.config.recordList)
    return ret['records']
  
  def deleteRecord(self, record: str):
    records = self.listRecord()
    for rec in records:
      if rec['name'] == record:
        self.send(self.config.recordDelete, { 'record_id': rec['id'] })
  
  def ensureTxtRecord(self, record: str, value: str):
    self.deleteRecord(record)
    data = { 'sub_domain': record, 'record_type': 'TXT', 'record_line_id': 0, 'value': value }
    self.send(self.config.recordCreate, data)

class ACMEError(Exception):
  def __init__(self, url: str, status: int, details: dict):
    self.url = url
    self.status = status
    self.details = details
  
  def __str__(self):
    details = json.dumps(self.details)
    return "error during ACME operation {}, status={}, details={}".format(
      self.url, self.status, details)

class ACMEClient:
  def __init__(self, config: Config, logger: LoggerBase=DummyLogger()):
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
      key = serial.load_ssh_private_key(keyRaw, secret.encode(self.config.encoding))
    if not isinstance(key, rsa.RSAPrivateKey):
      raise ValueError("Only RSAPrivateKey is supported, got {}".format(type(key)))
    self.keyPriv = key
    self.keyPub  = key.public_key()
    keyJWK = jwk.RSAKey(self.keyPub, self.keyAlg).to_dict()
    if 'alg' in keyJWK:
      del keyJWK['alg']
    self.keyJWK = keyJWK
    self.keyPrint = self.sha256(self.keyJWK)
    self.logger("keyPrint={}", self.keyPrint)
  
  def toJSON(self, x: dict):
    return json.dumps(x, separators=(",", ":"), sort_keys=True).encode(self.config.encoding)
  
  def toBytes(self, x: Union[bytes, str, dict]):
    if isinstance(x, str):
      x = x.encode(self.config.encoding)
    elif isinstance(x, dict):
      x = self.toJSON(x)
    elif not isinstance(x, bytes):
      raise TypeError()
    return x
  
  def sha256(self, x: Union[bytes, str, dict]):
    digest = hashes.Hash(hashes.SHA256())
    digest.update(self.toBytes(x))
    return self.urlbase64(digest.finalize())

  def urlbase64(self, x: Union[bytes, str, dict]):
    return base64.urlsafe_b64encode(self.toBytes(x)).decode(self.config.encoding).replace('=', '')
  
  def getNonce(self):
    resp = requests.head(self.config.newNonce)
    return resp.headers['Replay-Nonce']
  
  def sign(self, url: str, payload: Optional[dict]):
    nonce = self.getNonce()
    header = { 'alg': self.keyAlg, 'nonce': nonce, 'url': url }
    if self.keyID is not None:
      header['kid'] = self.keyID
    else:
      header['jwk'] = self.keyJWK
    headerEnc = self.urlbase64(header)
    if payload is None:
      payloadEnc = ""
    else:
      payloadEnc = self.urlbase64(payload)
    unsigned = '.'.join([headerEnc, payloadEnc]).encode(self.config.encoding)
    signature = self.keyPriv.sign(unsigned, self.padAlg(), self.hashAlg())
    signature = self.urlbase64(signature)
    return { 'protected': headerEnc, 'payload': payloadEnc, 'signature': signature }
  
  def signAndSend(self, url: str, payload: Optional[dict]):
    req = self.sign(url, payload)
    req = self.toJSON(req)
    self.logger("ACME request url={}", url)
    resp = requests.post(url, data=req, headers={ 'Content-Type': 'application/jose+json' })
    if resp.status_code != 200 and resp.status_code != 201:
      raise ACMEError(url, resp.status_code, resp.json())
    self.logger("response location={}", resp.headers.get('Location'))
    return resp
  
  def register(self, mail: Optional[str]=None):
    payload = { 'termsOfServiceAgreed': True }
    if mail is not None:
      payload['contact'] = [ "mailto: {}".format(mail) ]
    resp = self.signAndSend(self.config.newAccount, payload)
    self.keyID = resp.headers['Location']
    self.logger("register successful KID={}", self.keyID)

  def newOrder(self, domain: str):
    self.logger("newOrder domain={}", domain)
    payload = { 'identifiers': [{ 'type': 'dns', 'value': domain }] }
    resp = self.signAndSend(self.config.newOrder, payload)
    return resp.headers['Location'], resp.json()
  
  def getAsPost(self, url: str, text: bool=False):
    self.logger("get as post request location={}", url)
    resp = self.signAndSend(url, None)
    if text:
      return resp.text
    else:
      return resp.json()
  
  def getChallenge(self, authURL: str):
    auth = self.getAsPost(authURL)
    challenge = None
    for chall in auth['challenges']:
      if chall['type'] == 'dns-01':
        challenge = chall
        break
    if challenge is None:
      raise RuntimeError("No valid challenge found auth={}".format(authURL))
    domain = "_acme-challenge." + auth['identifier']['value']
    authVal = '.'.join([challenge['token'], self.keyPrint])
    return challenge['url'], domain, self.sha256(authVal)
  
  def finalize(self, finalURL: str, csr: x509.CertificateSigningRequest):
    csrEnc = self.urlbase64(csr.public_bytes(serial.Encoding.DER))
    self.signAndSend(finalURL, { 'csr': csrEnc })

class GetSSL:
  def __init__(self, configPath: str, domain: str):
    self.domain = domain
    self.logger = DebugLogger(True)
    self.config = Config(configPath, self.logger)
    self.acme   = ACMEClient(self.config, self.logger)
    self.dnspod = DNSPodClient(self.config, self.logger)

  def waitForStatusValid(self, url: str, expect: str, sleep: int=1, retry: int=5):
    self.logger("wait for {} to be {}", url, expect)
    while True:
      obj = self.acme.getAsPost(url)
      retry -= 1
      status = obj['status']
      if status == expect:
        return obj
      elif status not in ( 'valid', 'pending', 'ready', 'processing' ):
        raise RuntimeError("wait object valid failed url={}, status={}".format(url, status))
      elif retry <= 0:
        raise RuntimeError("wait object valid timeout url={}".format(url))
      time.sleep(sleep)
  
  def getCSR(self, keySize: int=4096):
    self.logger("generate CSR domain={}, keySize={}", self.domain, keySize)
    builder = x509.CertificateSigningRequestBuilder()
    builder = builder.subject_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, self.domain)]))
    builder = builder.add_extension(x509.BasicConstraints(False, None), True)
    priv = rsa.generate_private_key(65537, keySize)
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

  def saveSSL(self, priv: rsa.RSAPrivateKey, csr: x509.CertificateSigningRequest, cert: str):
    baseName = datetime.now().strftime('%Y-%m-%d')
    if self.domain.startswith('*.'):
      basePath = os.path.join(self.config.wd, 'wildcard', self.domain[2:], baseName)
    else:
      basePath = os.path.join(self.config.wd, self.domain, baseName)
    os.makedirs(basePath, 0o700)
    self.logger("save cert to basePath={}".format(basePath))
    
    privPath = os.path.join(basePath, 'rsa-{}'.format(baseName))
    with self.openForSafeWrite(privPath) as fout:
      secret = getpass(prompt="Enter passphrase for key '{}': ".format(privPath)).encode(self.config.encoding)
      encrypt = serial.BestAvailableEncryption(secret)
      privEnc = priv.private_bytes(serial.Encoding.PEM, serial.PrivateFormat.TraditionalOpenSSL, encrypt)
      fout.write(privEnc)
    self.logger("save privKey path={}", privPath)
    
    csrPath = os.path.join(basePath, 'rsa-{}.csr'.format(baseName))
    with self.openForSafeWrite(csrPath) as fout:
      csrEnc = csr.public_bytes(serial.Encoding.PEM)
      fout.write(csrEnc)
    self.logger("save CSR path={}", csrPath)

    certPath = os.path.join(basePath, 'rsa-{}.ca_bundle'.format(baseName))
    with self.openForSafeWrite(certPath) as fout:
      certEnc = cert.encode(self.config.encoding)
      fout.write(certEnc)
    self.logger("save ca_bundle path={}", certPath)

  def getSSL(self):
    orderURL, order = self.acme.newOrder(self.domain)
    authURL = order['authorizations'][0]
    self.logger("new order location={}, auth={}", orderURL, authURL)
    
    challengeURL, challengeDomain, challengeValue = self.acme.getChallenge(authURL)
    self.dnspod.ensureTxtRecord(self.dnspod.recordFromDomain(challengeDomain), challengeValue)
    self.logger("challenge record written domain={}", challengeDomain)

    priv, csr = self.getCSR()
    
    self.acme.signAndSend(challengeURL, {})
    order = self.waitForStatusValid(authURL, 'valid')
    order = self.waitForStatusValid(orderURL, 'ready')
    finalURL = order['finalize']
    self.logger("order ready finalize={}", finalURL)
    
    self.acme.finalize(finalURL, csr)
    order = self.waitForStatusValid(orderURL, 'valid')
    certURL = order['certificate']
    self.logger("cert issued url={}", certURL)
    
    cert = self.acme.getAsPost(certURL, True)
    return priv, csr, cert

  def run(self):
    self.acme.register()
    priv, csr, cert = self.getSSL()
    self.saveSSL(priv, csr, cert)

if __name__ == '__main__':
  if len(sys.argv) < 2:
    raise ValueError('Must provide config file and domain')
  GetSSL(sys.argv[1], sys.argv[2]).run()
