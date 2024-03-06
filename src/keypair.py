"""A Kubernetes controller based on kopf that responsible for generating an SSH key pair and storing it as a secret"""

import os
import logging
import base64
import datetime
import kopf
import kubernetes
import yaml
from croniter import croniter

from cryptography.hazmat.primitives import serialization as crypto_serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend as crypto_default_backend

PUBLIC_EXPONENT_DEFAULT = 65537

@kopf.on.create('keypair.looty.com', 'v1', 'keypair')
def on_create(body, patch, **kwargs):
    """On create callback"""

    name = body["metadata"]["name"]
    namespace = body["metadata"]["namespace"]
    rotate_for = body["spec"]["rotateFor"]

    private_key_size = body["spec"]["privateKey"]["size"]
    private_key_algorithm = body["spec"]["privateKey"]["algorithm"]
    private_key_encoding = body["spec"]["privateKey"]["encoding"]

    gen_private_key, gen_public_key = generate_keypair(
        PUBLIC_EXPONENT_DEFAULT,
        private_key_size,
        private_key_encoding,
        private_key_algorithm
    )

    create_keypair_secret(name, namespace, gen_private_key, gen_public_key)
    logging.info("SSH keypair '%s' secret was created!", name)

    patch.spec["rotationIndex"] = rotate_for

@kopf.on.update('keypair.looty.com', 'v1', 'keypair')
def on_update(body, meta, spec, status, old, new, diff, **kwargs):
    """On update callback"""

    pass

# @kopf.on.field('keypair.looty.com', 'v1', 'keypair', field='spec.rotationIndex')
# def skip_rotation_index(old, new, status, namespace, **kwargs):
#     """Event triggers when spec.rotationIndex was changed"""

#     pass

@kopf.timer('keypair.looty.com', 'v1', 'keypair', interval=60, sharp=True)
def on_timer(name, namespace, patch, spec, **kwargs):
    """On timer callback"""

    cron_time = spec["rotateAt"]
    rotate_for = spec["rotateFor"]
    rotation_index = spec["rotationIndex"]

    if rotate_for <= 0:
        pass

    if rotate_for > 0 and rotation_index != 0:
        cron = croniter(cron_time, datetime.datetime.now())
        next_time = cron.get_next(datetime.datetime)
        if next_time >= datetime.datetime.now():
            gen_private_key, gen_public_key = generate_keypair(
                PUBLIC_EXPONENT_DEFAULT,
                spec["privateKey"]["size"],
                spec["privateKey"]["encoding"],
                spec["privateKey"]["algorithm"]
            )

            if rotation_index > 0:
                patch.spec["rotationIndex"] = rotation_index - 1
                rotation_index = rotation_index - 1
            else:
                logging.info("Careful! on keypair '%s' rotationIndex <= 0 on tick!", name)

            index = rotate_for - rotation_index
            new_name = f"{name}-{index}"

            api = kubernetes.client.CoreV1Api()

            logging.info("Deleting '%s' keypair if already exists..", new_name)
            try:
                api.delete_namespaced_secret(name=new_name, namespace=namespace)
            except Exception:
                print(f"Secret '{new_name}' not found in namespace '{namespace}', ignoring..")

            logging.info("Preparing to create a new SSH keypair '%s'..", new_name)
            create_keypair_secret(new_name, namespace, gen_private_key, gen_public_key)

    if rotation_index == 0 and rotate_for > 0:
        patch.spec["rotationIndex"] = rotate_for

@kopf.on.delete('keypair.looty.com', 'v1', 'keypair')
def on_delete(body, meta, spec, status, **kwargs):
    """On delete callback"""

    pass

def get_algorithm(algorithm):
    """Returns class algorithm of choice"""

    algorithm_map = {
        "PKCS1": crypto_serialization.PrivateFormat.TraditionalOpenSSL,
        "PKCS8": crypto_serialization.PrivateFormat.PKCS8,
        "RAW": crypto_serialization.PrivateFormat.Raw,
        "OPENSSH": crypto_serialization.PrivateFormat.OpenSSH,
    }

    if algorithm.upper() in algorithm_map:
        return algorithm_map[algorithm.upper()]
    else:
        raise ValueError(
            "Invalid input string. Only 'PKCS1' or 'PKCS8' or 'Raw' or 'OpenSSH' are supported."
        )

    return algorithm_map[algorithm.upper()]

def get_encoding(encoding):
    """Returns class encoding of choice"""

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
        raise ValueError(
            "Invalid input string. Only 'PEM' or 'DER' or 'OPENSSH' or 'RAW' or 'X962' or 'SMIME' are supported."
        )

def generate_keypair(public_exponent, key_size, private_key_encoding, private_key_algorithm):
    """Returns generated private and public keys"""

    key = rsa.generate_private_key(
        backend=crypto_default_backend(),
        public_exponent=public_exponent,
        key_size=key_size
    )

    private_key = key.private_bytes(
        get_encoding(private_key_encoding),
        get_algorithm(private_key_algorithm),
        crypto_serialization.NoEncryption()
    )

    public_key = key.public_key().public_bytes(
        crypto_serialization.Encoding.OpenSSH,
        crypto_serialization.PublicFormat.OpenSSH
    )

    return private_key, public_key

def create_keypair_secret(name, namespace, private_key, public_key):
    """Creates a kubernetes secret"""

    path = os.path.join(os.path.dirname(__file__), '..', 'templates', 'keypair.yaml')
    with open(path, 'rt', encoding="utf-8") as file:
        tmpl = file.read()
    text = tmpl.format(
        name=name,
        private_key=base64.b64encode(private_key).decode(),
        public_key=base64.b64encode(public_key).decode()
    )

    data = yaml.safe_load(text)
    api = kubernetes.client.CoreV1Api()
    api.create_namespaced_secret(
        namespace=namespace,
        body=data,
    )
