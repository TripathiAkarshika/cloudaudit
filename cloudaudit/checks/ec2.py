"""EC2/VPC checks: exposed security groups, EBS encryption, IMDSv2."""

from cloudaudit.findings import Finding, Severity
from cloudaudit.registry import check

ANYWHERE = ("0.0.0.0/0", "::/0")


def _open_to_world(permission) -> bool:
    v4 = any(r.get("CidrIp") in ANYWHERE for r in permission.get("IpRanges", []))
    v6 = any(r.get("CidrIpv6") in ANYWHERE for r in permission.get("Ipv6Ranges", []))
    return v4 or v6


def _covers_port(permission, port: int) -> bool:
    if permission.get("IpProtocol") == "-1":
        return True
    lo, hi = permission.get("FromPort"), permission.get("ToPort")
    if lo is None or hi is None:
        return False
    return lo <= port <= hi


def _port_check(session, region, check_id, title, port, cis):
    ec2 = session.client("ec2", region_name=region)
    findings = []
    for page in ec2.get_paginator("describe_security_groups").paginate():
        for sg in page["SecurityGroups"]:
            for perm in sg.get("IpPermissions", []):
                if _open_to_world(perm) and _covers_port(perm, port):
                    findings.append(Finding(
                        check_id=check_id, title=title,
                        severity=Severity.HIGH, service="ec2",
                        resource=f"{sg['GroupId']} ({sg['GroupName']})", region=region,
                        description=f"Ingress from 0.0.0.0/0 reaches port {port}.",
                        cis=cis))
                    break
    return findings


@check("EC2_001", "Security group open to the world on SSH (22)", "ec2", "regional", "5.2")
def ssh_open(session, region):
    return _port_check(session, region, "EC2_001",
                       "Security group open to the world on SSH (22)", 22, "5.2")


@check("EC2_002", "Security group open to the world on RDP (3389)", "ec2", "regional", "5.2")
def rdp_open(session, region):
    return _port_check(session, region, "EC2_002",
                       "Security group open to the world on RDP (3389)", 3389, "5.2")


@check("EC2_003", "Security group allows all traffic from anywhere", "ec2", "regional",
       "best practice")
def all_open(session, region):
    ec2 = session.client("ec2", region_name=region)
    findings = []
    for page in ec2.get_paginator("describe_security_groups").paginate():
        for sg in page["SecurityGroups"]:
            for perm in sg.get("IpPermissions", []):
                if perm.get("IpProtocol") == "-1" and _open_to_world(perm):
                    findings.append(Finding(
                        check_id="EC2_003",
                        title="Security group allows all traffic from anywhere",
                        severity=Severity.CRITICAL, service="ec2",
                        resource=f"{sg['GroupId']} ({sg['GroupName']})", region=region,
                        description="Ingress rule allows every protocol and port "
                                    "from 0.0.0.0/0.",
                        cis="best practice"))
                    break
    return findings


@check("EC2_004", "Default security group allows traffic", "ec2", "regional", "5.3")
def default_sg(session, region):
    ec2 = session.client("ec2", region_name=region)
    findings = []
    for page in ec2.get_paginator("describe_security_groups").paginate(
            Filters=[{"Name": "group-name", "Values": ["default"]}]):
        for sg in page["SecurityGroups"]:
            if sg.get("IpPermissions") or sg.get("IpPermissionsEgress"):
                findings.append(Finding(
                    check_id="EC2_004", title="Default security group allows traffic",
                    severity=Severity.MEDIUM, service="ec2",
                    resource=sg["GroupId"], region=region,
                    description="The default security group should have no inbound or "
                                "outbound rules so accidental use grants nothing.",
                    cis="5.3"))
    return findings


@check("EC2_005", "EBS volume not encrypted", "ec2", "regional", "2.2.1")
def unencrypted_volumes(session, region):
    ec2 = session.client("ec2", region_name=region)
    findings = []
    for page in ec2.get_paginator("describe_volumes").paginate():
        for vol in page["Volumes"]:
            if not vol.get("Encrypted"):
                findings.append(Finding(
                    check_id="EC2_005", title="EBS volume not encrypted",
                    severity=Severity.MEDIUM, service="ec2",
                    resource=vol["VolumeId"], region=region,
                    description="Volume is not encrypted at rest.",
                    cis="2.2.1"))
    return findings


@check("EC2_006", "EBS encryption by default disabled", "ec2", "regional", "2.2.1")
def ebs_encryption_by_default(session, region):
    ec2 = session.client("ec2", region_name=region)
    if not ec2.get_ebs_encryption_by_default()["EbsEncryptionByDefault"]:
        return [Finding(
            check_id="EC2_006", title="EBS encryption by default disabled",
            severity=Severity.MEDIUM, service="ec2",
            resource=f"account-setting/{region}", region=region,
            description="New EBS volumes in this region are not encrypted automatically.",
            cis="2.2.1")]
    return []


@check("EC2_007", "Instance does not enforce IMDSv2", "ec2", "regional", "5.6")
def imdsv2(session, region):
    ec2 = session.client("ec2", region_name=region)
    findings = []
    for page in ec2.get_paginator("describe_instances").paginate():
        for res in page["Reservations"]:
            for inst in res["Instances"]:
                if inst.get("State", {}).get("Name") == "terminated":
                    continue
                opts = inst.get("MetadataOptions", {})
                if opts.get("HttpTokens") != "required":
                    findings.append(Finding(
                        check_id="EC2_007", title="Instance does not enforce IMDSv2",
                        severity=Severity.MEDIUM, service="ec2",
                        resource=inst["InstanceId"], region=region,
                        description="Instance metadata service accepts IMDSv1 requests "
                                    "(HttpTokens is not 'required'), enabling SSRF "
                                    "credential theft.",
                        cis="5.6"))
    return findings
