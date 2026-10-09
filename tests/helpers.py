"""Test helpers."""
from core.models import Resource
from rules import CloudEnv


def sg(rid="sg-test", cidr="0.0.0.0/0", port=22, proto="tcp", to_port=None):
    return Resource(resource_type="SecurityGroup", resource_id=rid, properties={
        "ingress": [{"cidr": cidr, "protocol": proto, "from_port": port, "to_port": to_port or port}]})


def env_of(*resources):
    return CloudEnv(list(resources))
