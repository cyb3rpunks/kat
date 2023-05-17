import paramiko
import json
from boefjes.job_models import BoefjeMeta


def run_ssh_cyphers(ip_address, port, username, password: List[str]) -> dict:
    """Checks SSH Cyphers avialable on ssh server"""
  # Create an SSH client
    client = paramiko.SSHClient()
    try:
        # Automatically add the server's host key (disable if not desired)
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        # Connect to the SSH server
        client.connect(ip_address, port, username, password)
        print("Connected to SSH server.")
        # Get the transport object from the client
        transport = client.get_transport()
        # Get the list of supported ciphers
        ciphers = transport.get_security_options().ciphers
        result = {"Available SSH Ciphers": ciphers}
        json_result = json.dumps(result, indent=4)
        return json_result

    except paramiko.AuthenticationException:
        print("Authentication failed.")
    except paramiko.SSHException as e:
        print("SSH connection failed:", str(e))
    finally:
        # Close the SSH client connection
        client.close()



def run(boefje_meta: BoefjeMeta) -> List[Tuple[set, Union[bytes, str]]]:
    """return results to normalizer."""
    input_ = boefje_meta.arguments["input"]
    ip_address = input_["address"]
    username = getenv("username")
    password = getenv("password")
    port = 22
    results = run_ssh_cyphers(ip_address, port, username, password)
    return [(set(), json.dumps(results))]



