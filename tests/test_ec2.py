from cloudaudit.checks import ec2 as ec2_checks
from tests.conftest import REGION, resources

AMI = "ami-12c6146b"  # any id works under moto


def sg(aws, name):
    ec2 = aws.client("ec2", region_name=REGION)
    return ec2.create_security_group(GroupName=name, Description=name)["GroupId"]


def open_port(aws, group_id, port, cidr="0.0.0.0/0"):
    aws.client("ec2", region_name=REGION).authorize_security_group_ingress(
        GroupId=group_id,
        IpPermissions=[{"IpProtocol": "tcp", "FromPort": port, "ToPort": port,
                        "IpRanges": [{"CidrIp": cidr}]}])


def test_ssh_open_to_world_flagged(aws):
    gid = sg(aws, "ssh-open")
    open_port(aws, gid, 22)
    found = resources(ec2_checks.ssh_open(aws, REGION))
    assert any(gid in r for r in found)


def test_ssh_from_office_cidr_passes(aws):
    gid = sg(aws, "ssh-office")
    open_port(aws, gid, 22, cidr="10.20.0.0/16")
    found = resources(ec2_checks.ssh_open(aws, REGION))
    assert not any(gid in r for r in found)


def test_rdp_open_to_world_flagged(aws):
    gid = sg(aws, "rdp-open")
    open_port(aws, gid, 3389)
    found = resources(ec2_checks.rdp_open(aws, REGION))
    assert any(gid in r for r in found)


def test_all_traffic_open_flagged(aws):
    ec2 = aws.client("ec2", region_name=REGION)
    gid = sg(aws, "wide-open")
    ec2.authorize_security_group_ingress(
        GroupId=gid,
        IpPermissions=[{"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
    found = resources(ec2_checks.all_open(aws, REGION))
    assert any(gid in r for r in found)


def test_default_sg_with_rules_flagged(aws):
    # moto's default VPC ships a default security group with rules in place.
    assert ec2_checks.default_sg(aws, REGION) != []


def test_unencrypted_volume_flagged(aws):
    ec2 = aws.client("ec2", region_name=REGION)
    plain = ec2.create_volume(AvailabilityZone=f"{REGION}a", Size=8)["VolumeId"]
    crypt = ec2.create_volume(AvailabilityZone=f"{REGION}a", Size=8,
                              Encrypted=True)["VolumeId"]
    found = resources(ec2_checks.unencrypted_volumes(aws, REGION))
    assert plain in found
    assert crypt not in found


def test_ebs_encryption_by_default(aws):
    ec2 = aws.client("ec2", region_name=REGION)
    assert ec2_checks.ebs_encryption_by_default(aws, REGION) != []
    ec2.enable_ebs_encryption_by_default()
    assert ec2_checks.ebs_encryption_by_default(aws, REGION) == []


def test_imdsv1_instance_flagged(aws):
    ec2 = aws.client("ec2", region_name=REGION)
    v1 = ec2.run_instances(ImageId=AMI, MinCount=1, MaxCount=1,
                           MetadataOptions={"HttpTokens": "optional"})
    v2 = ec2.run_instances(ImageId=AMI, MinCount=1, MaxCount=1,
                           MetadataOptions={"HttpTokens": "required"})
    v1_id = v1["Instances"][0]["InstanceId"]
    v2_id = v2["Instances"][0]["InstanceId"]

    found = resources(ec2_checks.imdsv2(aws, REGION))
    assert v1_id in found
    assert v2_id not in found
