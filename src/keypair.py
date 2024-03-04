import kopf
import logging
import kubernetes
import yaml
import base64

from cryptography.hazmat.primitives import serialization as crypto_serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend as crypto_default_backend

@kopf.on.create('keypair.looty.com', 'v1', 'keypair')
def on_create(body, **kwargs):
    public_exponent = 65537

    name = body["metadata"]["name"]
    namespace = body["metadata"]["namespace"]
    rotate_for = body["spec"]["rotateFor"]
    rotate_at = body["spec"]["roateAt"]

    private_key = body["spec"]["privateKey"]
    private_key_size = body["spec"]["privateKey"]["size"]
    private_key_algorithm = body["spec"]["privateKey"]["algorithm"]
    private_key_encoding = body["spec"]["privateKey"]["encoding"]

    logging.info(f"A handler is called with body: {name, namespace, rotate_for, rotate_at, private_key}")

    gen_key = rsa.generate_private_key(
        backend=crypto_default_backend(),
        public_exponent=public_exponent,
        key_size=private_key_size
    )

    gen_private_key = gen_key.private_bytes(
        get_encoding(private_key_encoding),
        get_algorithm(private_key_algorithm),
        crypto_serialization.NoEncryption()
    )

    gen_public_key = gen_key.public_key().public_bytes(
        crypto_serialization.Encoding.OpenSSH,
        crypto_serialization.PublicFormat.OpenSSH
    )

    logging.info(f"gen_key: {gen_key}")
    logging.info(f"gen_private_key: {gen_private_key}")
    logging.info(f"gen_public_key: {gen_public_key}")

    # Render the pod yaml with some spec fields used in the template.
    data = yaml.safe_load(f"""
        apiVersion: v1
        kind: Secret
        metadata:
          name: {name}
        type: Opaque
        data:
          private_key: {base64.b64encode(gen_private_key).decode()}
          public_key: {base64.b64encode(gen_public_key).decode()}
    """)

    api = kubernetes.client.CoreV1Api()
    secret = api.create_namespaced_secret(
        namespace=namespace,
        body=data,
    )

    logging.info(f"SSH secret is created!")

@kopf.on.update('keypair.looty.com', 'v1', 'keypair')
def update(body, meta, spec, status, old, new, diff, **kwargs):
    print('Handling the diff..')
    pprint.pprint(list(diff))

@kopf.on.delete('keypair.looty.com', 'v1', 'keypair')
def delete(body, meta, spec, status, **kwargs):
    print('Handling delete..')
    pprint.pprint(body)

def get_algorithm(algorithm):
    logging.info(f"Algorithm choice: {algorithm}")

    algorithm_map = {
        "PKCS1": crypto_serialization.PrivateFormat.TraditionalOpenSSL,
        "PKCS8": crypto_serialization.PrivateFormat.PKCS8,
        "RAW": crypto_serialization.PrivateFormat.Raw,
        "OPENSSH": crypto_serialization.PrivateFormat.OpenSSH,
    }

    if algorithm.upper() in algorithm_map:
        return algorithm_map[algorithm.upper()]
    else:
        raise ValueError("Invalid input string. Only 'PKCS1' or 'PKCS8' or 'Raw' or 'OpenSSH' are supported.")

def get_encoding(encoding):
    logging.info(f"Encoding choice: {encoding}")

    encoding_map = {
        "PEM": crypto_serialization.Encoding.PEM,
        "DER": crypto_serialization.Encoding.DER,
        "OPENSSH": crypto_serialization.Encoding.OpenSSH,
        "RAW": crypto_serialization.Encoding.Raw,
        "X962": crypto_serialization.Encoding.X962,
        "SMIME": crypto_serialization.Encoding.SMIME,
    }

    if encoding.upper() in encoding_map:
        return encoding_map[encoding.upper()]
    else:
        raise ValueError("Invalid input string. Only 'PEM' or 'DER' or 'OPENSSH' or 'RAW' or 'X962' or 'SMIME' are supported.")
