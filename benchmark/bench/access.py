"""Refresh only controller SSH rules on the saved owned testbed."""
import ipaddress
from .config import Settings
from .instance import InstanceManager
import alibaba_deployment as cloud


def update(settings,cidr,nodes=4):
    address=ipaddress.ip_network(cidr,strict=True)
    if address.version!=4 or address.prefixlen!=32:raise ValueError('one controller IPv4 /32 required')
    selected=Settings(settings);manager=InstanceManager(selected,int(nodes));results=[]
    with cloud.lease_lock(selected.root/'dispatch'),cloud.lease_lock(manager.base/'lifecycle'):
        record=manager.load()
        if not record or record.get('closed') or not record['leases']:raise ValueError('live owned testbed required')
        for path in record['leases']:
            with cloud.lease_lock(path):
                lease=cloud.Lease(path);m=lease.models;p=lease.plan
                if lease.state.get('closed'):raise ValueError('lease is closed')
                group=lease.state['security_group']
                groups=lease.call('describe_security_groups',m.DescribeSecurityGroupsRequest(region_id=p['region'],security_group_id=group,page_size=100))
                cloud.owned_security_group(groups['SecurityGroups']['SecurityGroup'],lease.state['run_id'],group)
                old=lease.state.get('controller_ssh_cidr',p['controller_cidr'])
                lease.state['controller_ssh_pending']={'from':old,'to':str(address)};cloud.save(lease.path,lease.state)
                lease.call('authorize_security_group',m.AuthorizeSecurityGroupRequest(region_id=p['region'],security_group_id=group,
                    permissions=[m.AuthorizeSecurityGroupRequestPermissions(ip_protocol='TCP',port_range='22/22',source_cidr_ip=str(address),description='Delugi controller SSH')]))
                if old!=str(address):
                    lease.call('revoke_security_group',m.RevokeSecurityGroupRequest(region_id=p['region'],security_group_id=group,
                        permissions=[m.RevokeSecurityGroupRequestPermissions(ip_protocol='TCP',port_range='22/22',source_cidr_ip=old)]))
                lease.state['controller_ssh_cidr']=str(address);lease.state.pop('controller_ssh_pending');cloud.save(lease.path,lease.state)
                results.append({'region':p['region'],'controller_cidr':str(address),'previous_cidr':old})
    return results
