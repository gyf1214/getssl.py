from abc import ABCMeta, abstractmethod
from typing import cast
import requests

from .log import LoggerBase
from .typing import JsonDict, JsonList

class DNSPodConfig(metaclass=ABCMeta):
  @property
  @abstractmethod
  def dnspodToken(self) -> str: pass

  @property
  @abstractmethod
  def baseDomain(self) -> str: pass

  @property
  @abstractmethod
  def recordList(self) -> str: pass

  @property
  @abstractmethod
  def recordDelete(self) -> str: pass

  @property
  @abstractmethod
  def recordCreate(self) -> str: pass

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
  def __init__(self, config: DNSPodConfig, logger: LoggerBase):
    self.config = config
    self.logger = logger
    self.token  = config.dnspodToken
    self.domain = config.baseDomain
  
  def send(self, url: str, data: JsonDict={}):
    x: JsonDict = { 'domain': self.domain, 'login_token': self.token, 'format': 'json', 'lang': 'en' }
    x.update(data)
    self.logger("DNSPod request url={}", url)
    resp = requests.post(url, x)
    ret: JsonDict = resp.json()
    retStatus = cast(JsonDict, ret['status'])
    code = int(cast(str, retStatus['code']))
    if resp.status_code != 200 or code != 1:
      msg = cast(str, retStatus['message'])
      raise DNSPodError(url, resp.status_code, code, msg)
    return ret
  
  def recordFromDomain(self, domain: str):
    suffix = '.' + self.domain
    if domain.endswith(suffix):
      domain = domain[:-len(suffix)]
    return domain
  
  def listRecord(self):
    ret = self.send(self.config.recordList)
    return cast(JsonList, ret['records'])
  
  def deleteRecord(self, record: str):
    records = self.listRecord()
    for rec in records:
      rec = cast(JsonDict, rec)
      if cast(str, rec['name']) == record:
        self.send(self.config.recordDelete, { 'record_id': rec['id'] })
  
  def ensureTxtRecord(self, record: str, value: str):
    self.deleteRecord(record)
    data: JsonDict = { 'sub_domain': record, 'record_type': 'TXT', 'record_line_id': 0, 'value': value }
    self.send(self.config.recordCreate, data)
