"""Pin the authenticated lane-M holding object and manifest."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
from urllib.parse import urlsplit

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

STATE = Path("/var/lib/jetstreamer/horizon_runtime_data/epoch185-lanem-holding-20261127-v1")
BUCKET = "solana-archive-with-accounts-data"
OWNER = "node_02/owner.json"


def client():
    endpoint = urlsplit(os.environ["HORIZON_S3_ENDPOINT"])
    assert endpoint.scheme == "https" and endpoint.path.strip("/") == BUCKET
    return boto3.client(
        "s3",
        endpoint_url=f"{endpoint.scheme}://{endpoint.netloc}",
        aws_access_key_id=os.environ["HORIZON_ACCESS_KEY_ID"],
        aws_secret_access_key=os.environ["HORIZON_SECRET_ACCESS_KEY"],
        region_name="auto",
        config=Config(
            signature_version="s3v4",
            s3={"addressing_style": "path"},
            connect_timeout=10,
            read_timeout=60,
            retries={"max_attempts": 3},
        ),
    )


def head(r2, key, etag=None):
    pin = {"IfMatch": etag} if etag else {}
    try:
        result = r2.head_object(Bucket=BUCKET, Key=key, **pin)
    except ClientError as error:
        if error.response["ResponseMetadata"]["HTTPStatusCode"] != 404:
            raise
        return {"key": key, "status": 404}
    metadata = result["ResponseMetadata"]
    assert metadata["HTTPStatusCode"] == 200
    return {
        "key": key,
        "status": 200,
        "etag": result["ETag"],
        "length": result["ContentLength"],
        "metadata": result["Metadata"],
        "request_id": metadata.get("RequestId") or metadata.get("HTTPHeaders", {}).get("cf-ray"),
    }


def small_body(r2, info):
    assert info["status"] == 200 and 0 < info["length"] < 16_384
    response = r2.get_object(Bucket=BUCKET, Key=info["key"], IfMatch=info["etag"])
    try:
        data = response["Body"].read(16_384)
    finally:
        response["Body"].close()
    assert response["ResponseMetadata"]["HTTPStatusCode"] == 200
    assert response["ETag"] == info["etag"] and len(data) == info["length"]
    return data


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("phase", choices=["precheck", "accepted"])
    phase = parser.parse_args().phase
    expected = json.loads((STATE / "package/EXPECTED.json").read_bytes())
    r2 = client()
    owner = head(r2, OWNER)
    assert json.loads(small_body(r2, owner)) == {
        "schema": "jetstreamer-horizon-holding-owner-v2",
        "host": "dev-samjohnson",
        "prefix": "node_02/",
    }
    wanted_etag = None
    if phase == "accepted":
        receipt = json.loads(Path(expected["custody_path"]).read_bytes())
        assert receipt["remote_sha256_readback"] is True
        assert receipt["local_source_revalidated"] is True
        assert receipt["local_retirement_authorized"] is False
        assert receipt["canonical_publication_authorized"] is False
        fields = ("source", "object_key", "manifest_key", "length", "sha256", "manifest_sha256", "manifest")
        assert all(receipt[key] == expected[key] for key in fields)
        wanted_etag = '"' + receipt["object_etag"].strip('"') + '"'
    blob = head(r2, expected["object_key"], wanted_etag)
    manifest = head(r2, expected["manifest_key"])
    if blob["status"] == 200:
        assert blob["length"] == expected["length"]
        assert blob["metadata"].get("sha256") == expected["sha256"]
    if manifest["status"] == 200:
        data = small_body(r2, manifest)
        assert hashlib.sha256(data).hexdigest() == expected["manifest_sha256"]
        assert json.loads(data) == expected["manifest"]
    if phase == "accepted":
        assert blob["status"] == manifest["status"] == 200
        assert blob["etag"] == wanted_etag
    print(json.dumps({
        "observed_utc": datetime.now(timezone.utc).isoformat(),
        "phase": phase,
        "authenticated": True,
        "owner": owner,
        "blob": blob,
        "manifest": manifest,
        "remote_mutations": False,
    }, indent=2), flush=True)


if __name__ == "__main__":
    main()
