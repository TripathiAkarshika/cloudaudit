from cloudaudit.checks import cloudtrail as ct_checks
from tests.conftest import REGION, ids


def make_trail(aws, name="audit-trail", multi_region=True, validation=True):
    s3 = aws.client("s3")
    bucket = f"{name}-logs"
    s3.create_bucket(Bucket=bucket)
    ct = aws.client("cloudtrail", region_name=REGION)
    ct.create_trail(Name=name, S3BucketName=bucket,
                    IsMultiRegionTrail=multi_region,
                    EnableLogFileValidation=validation)
    ct.start_logging(Name=name)
    return ct


def test_no_trail_flagged(aws):
    assert ids(ct_checks.multi_region_trail(aws, REGION)) == {"CT_001"}


def test_multi_region_trail_passes(aws):
    make_trail(aws)
    assert ct_checks.multi_region_trail(aws, REGION) == []


def test_single_region_trail_still_flagged(aws):
    make_trail(aws, multi_region=False)
    assert ids(ct_checks.multi_region_trail(aws, REGION)) == {"CT_001"}


def test_log_validation_disabled_flagged(aws):
    make_trail(aws, name="no-validation", validation=False)
    assert ids(ct_checks.log_file_validation(aws, REGION)) == {"CT_002"}


def test_stopped_trail_flagged(aws):
    ct = make_trail(aws)
    assert ct_checks.trail_logging(aws, REGION) == []
    ct.stop_logging(Name="audit-trail")
    assert ids(ct_checks.trail_logging(aws, REGION)) == {"CT_003"}
