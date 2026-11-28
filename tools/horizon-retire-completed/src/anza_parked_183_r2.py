import hashlib
import json
import os
import sys
from pathlib import Path
from urllib.parse import urlsplit

import boto3
from botocore.config import Config

custody = json.loads(Path(sys.argv[1]).read_bytes())
endpoint = urlsplit(os.environ["HORIZON_S3_ENDPOINT"])
bucket = custody["bucket"]
if (endpoint.scheme != "https" or not (endpoint.hostname or "").endswith(".r2.cloudflarestorage.com")
        or endpoint.path.strip("/") != bucket or endpoint.username is not None
        or endpoint.query or endpoint.fragment):
    raise ValueError("unexpected R2 endpoint")
client = boto3.client(
    "s3", endpoint_url=f"https://{endpoint.netloc}", region_name="auto",
    aws_access_key_id=os.environ["HORIZON_ACCESS_KEY_ID"],
    aws_secret_access_key=os.environ["HORIZON_SECRET_ACCESS_KEY"],
    config=Config(s3={"addressing_style": "path"}, connect_timeout=10, read_timeout=15,
                  retries={"max_attempts": 1}),
)
etag = '"' + custody["object_etag"].strip('"') + '"'
head = client.head_object(Bucket=bucket, Key=custody["object_key"], IfMatch=etag)
if (head["ETag"] != etag or head["ContentLength"] != custody["length"]
        or head["Metadata"].get("sha256") != custody["sha256"]):
    raise ValueError("holding body differs from whole-readback receipt")
manifest = client.get_object(Bucket=bucket, Key=custody["manifest_key"])
with manifest["Body"] as body:
    if manifest["ContentLength"] > 4096:
        raise ValueError("oversized holding manifest")
    data = body.read()
    if hashlib.sha256(data).hexdigest() != custody["manifest_sha256"] or json.loads(data) != custody["manifest"]:
        raise ValueError("holding manifest differs from whole-readback receipt")
