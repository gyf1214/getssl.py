import sys
import time
from typing import cast
from cryptography import x509
import requests

from getssl.log import LoggerBase, DebugLogger, ConfigBase, Actor, StrDict
from getssl.certManager import CertManager, CertManagerConfig, KeyType
from getssl.dnspod import DNSPodClient, DNSPodConfig
from getssl.acme import ACMEClient, ACMEConfig
from getssl.typing import JsonDict, PrivateKeyTypes

class Config(ConfigBase, CertManagerConfig, DNSPodConfig, ACMEConfig):
  def __init__(self, path: str, logger: LoggerBase):
    super().__init__(path, logger)
    
    raw = self._raw
    self._wd = raw['workingDir']
    # CA
    self._ca         = raw['ca']
    self._allMethods: StrDict = requests.get(self._ca).json()
    self._accountKey = raw['accountKey']
    logger("CA url={}, accountKey={}", self._ca, self._accountKey)
    # dnspod
    self._dnspod       = raw['dnspod']
    self._dnspodToken  = raw['dnspodToken']
    self._baseDomain   = raw['baseDomain']
    logger("dnspod url={}, baseDomain={}", self._dnspod, self._baseDomain)
  
  @property
  def wd(self): return self._wd

  @property
  def recordList(self): return self._dnspod + '/Record.List'

  @property
  def recordCreate(self): return self._dnspod + '/Record.Create'

  @property
  def recordDelete(self): return self._dnspod + '/Record.Remove'

  @property
  def dnspodToken(self): return self._dnspodToken

  @property
  def baseDomain(self): return self._baseDomain

  @property
  def newAccount(self): return self._allMethods['newAccount']

  @property
  def newNonce(self): return self._allMethods['newNonce']

  @property
  def newOrder(self): return self._allMethods['newOrder']

  @property
  def accountKey(self): return self._accountKey

class GetSSL(Actor):
  def __init__(self, configPath: str, domain: str):
    self.domain = domain
    self.logger = DebugLogger(True)
    self.config = Config(configPath, self.logger)
    self.acme   = ACMEClient(self.config, self.logger)
    self.dnspod = DNSPodClient(self.config, self.logger)
    self.certManager = CertManager(self.config, self.logger)
    self.certManager.domain = domain

  def waitForStatusValid(self, url: str, expect: str, sleep: int=1, retry: int=5):
    self.logger("wait for {} to be {}", url, expect)
    while True:
      obj = cast(JsonDict, self.acme.getAsPost(url))
      retry -= 1
      status = cast(str, obj['status'])
      if status == expect:
        return obj
      elif status not in ( 'valid', 'pending', 'ready', 'processing' ):
        raise RuntimeError("wait object valid failed url={}, status={}, details={}".format(url, status, obj))
      elif retry <= 0:
        raise RuntimeError("wait object valid timeout url={}, status={}, details={}".format(url, status, obj))
      time.sleep(sleep)

  def saveSSL(self, priv: PrivateKeyTypes, csr: x509.CertificateSigningRequest, cert: str):
    keyType = KeyType.getType(priv)
    self.certManager.savePriv(priv)
    self.certManager.saveCSR(csr, keyType)
    self.certManager.saveCert(cert, keyType)

  def getSSL(self, dnsWait: int=5):
    orderURL, order = self.acme.newOrder(self.domain)
    authURL = order['authorizations'][0]
    self.logger("new order location={}, auth={}", orderURL, authURL)
    
    challengeURL, challengeDomain, challengeValue = self.acme.getChallenge(authURL)
    challengeRecord = self.dnspod.recordFromDomain(challengeDomain)
    try:
      self.dnspod.ensureTxtRecord(challengeRecord, challengeValue)
      self.logger("challenge record written domain={}", challengeDomain)
      self.logger("sleep {} secs for DNS", dnsWait)
      time.sleep(dnsWait)

      priv, csr = self.certManager.getCSR(KeyType.RSA)
      
      self.acme.signAndSend(challengeURL, {})
      order = self.waitForStatusValid(authURL, 'valid')
      order = self.waitForStatusValid(orderURL, 'ready')
      finalURL = cast(str, order['finalize'])
    except Exception as ex:
      raise ex from None
    finally:
      self.dnspod.deleteRecord(challengeRecord)
    self.logger("order ready finalize={}", finalURL)
    
    self.acme.finalize(finalURL, csr)
    order = self.waitForStatusValid(orderURL, 'valid')
    certURL = cast(str, order['certificate'])
    self.logger("cert issued url={}", certURL)
    
    cert = self.acme.getAsPost(certURL, True)
    return priv, csr, cast(str, cert)

  def run(self):
    self.acme.register()
    priv, csr, cert = self.getSSL()
    self.saveSSL(priv, csr, cert)

if __name__ == '__main__':
  if len(sys.argv) <= 2:
    raise ValueError('Must provide config file and domain')
  GetSSL(sys.argv[1], sys.argv[2]).run()
