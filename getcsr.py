import sys
from getssl.log import LoggerBase, DebugLogger, ConfigBase, Actor
from getssl.certManager import CertManager, CertManagerConfig, KeyType

class Config(ConfigBase, CertManagerConfig):
  def __init__(self, path: str, logger: LoggerBase):
    super().__init__(path, logger)
    raw = self._raw
    self._wd = raw['workingDir']

  @property
  def wd(self): return self._wd

class GetCSR(Actor):
  def __init__(self, config: str, domain: str, keyType: KeyType=KeyType.EC):
    self.logger = DebugLogger(True)
    self.config = Config(config, self.logger)
    self.certManager = CertManager(self.config, self.logger)
    self.certManager.domain = domain
    self.keyType = keyType
  
  def run(self):
    priv, csr = self.certManager.getCSR(self.keyType)
    self.certManager.saveCSR(csr, self.keyType)
    self.certManager.savePriv(priv)

if __name__ == '__main__':
  if len(sys.argv) <= 2:
    raise ValueError('Must provide config file and domain')
  GetCSR(sys.argv[1], sys.argv[2]).run()
