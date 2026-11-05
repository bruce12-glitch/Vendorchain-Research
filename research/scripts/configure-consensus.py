"""Derive four-node Raft from the pinned four-node BFT sample profile.

The sample's '-bft' flag selects four-node provisioning and is retained. Actual
consensus is checked from the committed channel block, never from that flag.
"""
import argparse
from pathlib import Path
import yaml


def configure(path, consensus):
    path=Path(path);value=yaml.safe_load(path.read_text())
    orderer=value['Profiles']['ChannelUsingBFT']['Orderer']
    if consensus=='etcdraft':
        mapping=orderer.pop('ConsenterMapping')
        orderer.pop('SmartBFT',None)
        orderer['OrdererType']='etcdraft'
        orderer['EtcdRaft']={'Consenters':[{k:m[k] for k in ('Host','Port','ClientTLSCert','ServerTLSCert')} for m in mapping],
                            'Options':{'TickInterval':'500ms','ElectionTick':10,'HeartbeatTick':1,'MaxInflightBlocks':5,'SnapshotIntervalSize':16777216}}
        # BFT-only ordering identities are absent from the Raft config.
        value['Capabilities']['Channel']={'V2_0':True}
        value['Profiles']['ChannelUsingBFT']['Capabilities']={'V2_0':True}
    elif consensus!='BFT':raise ValueError('consensus must be BFT or etcdraft')
    path.write_text(yaml.safe_dump(value,sort_keys=False))


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('path');p.add_argument('consensus',choices=['BFT','etcdraft'])
    a=p.parse_args();configure(a.path,a.consensus)
