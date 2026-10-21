#!/usr/bin/env python3
"""Read-only inventory using the local Loom settings; never serializes credentials."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path


def discover(settings_path):
    from alibabacloud_ecs20140526.client import Client
    from alibabacloud_ecs20140526 import models
    from alibabacloud_tea_openapi.models import Config
    from alibabacloud_tea_util.models import RuntimeOptions

    path = Path(settings_path).expanduser().resolve()
    settings = json.loads(path.read_text())
    credentials_path = Path(settings['key']['accesskey']).expanduser()
    if not credentials_path.is_absolute():
        credentials_path = path.parent / credentials_path
    credentials = json.loads(credentials_path.read_text())

    def region_inventory(region):
        client = Client(Config(access_key_id=credentials['AccessKey ID'],
            access_key_secret=credentials['AccessKey Secret'], region_id=region,
            endpoint=f'ecs.{region}.aliyuncs.com', read_timeout=20000, connect_timeout=20000))
        instances, page = [], 1
        try:
            while True:
                body = client.describe_instances_with_options(models.DescribeInstancesRequest(
                    region_id=region, page_number=page, page_size=100), RuntimeOptions()).to_map()['body']
                for item in body['Instances']['Instance']:
                    instances.append({
                        'id': item['InstanceId'], 'name': item.get('InstanceName'),
                        'status': item['Status'], 'type': item['InstanceType'],
                        'cpu': item.get('Cpu'), 'memory_mib': item.get('Memory'),
                        'public_ips': item.get('PublicIpAddress', {}).get('IpAddress', []),
                        'private_ips': item.get('VpcAttributes', {}).get('PrivateIpAddress', {}).get('IpAddress', []),
                        'key_pair': item.get('KeyPairName'), 'zone': item.get('ZoneId'),
                        'vpc_id': item.get('VpcAttributes', {}).get('VpcId'),
                        'security_groups': item.get('SecurityGroupIds', {}).get('SecurityGroupId', []),
                        'charge_type': item.get('InstanceChargeType'),
                        'network_charge_type': item.get('InternetChargeType'),
                        'outbound_mbps': item.get('InternetMaxBandwidthOut'),
                        'tags': item.get('Tags', {}).get('Tag', []),
                    })
                if page * 100 >= body['TotalCount']:
                    break
                page += 1
            return {'region': region, 'instances': instances}
        except Exception as error:
            # Provider exception strings can contain signed request details.
            return {'region': region, 'error_type': type(error).__name__,
                    'error_code': getattr(error, 'code', None)}

    regions = settings['instances']['regions']
    with ThreadPoolExecutor(max_workers=len(regions)) as pool:
        results = list(pool.map(region_inventory, regions))
    return {'provider': 'Alibaba Cloud', 'settings': str(path),
            'configured_type': settings['instances']['type'],
            'configured_key_pair': settings['key']['name'], 'regions': results}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--settings', required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    result = discover(args.settings)
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    Path(args.output).write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))
