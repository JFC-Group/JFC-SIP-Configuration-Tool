from urllib.parse import urlparse
from ssl import CERT_NONE, create_default_context
import argparse
import configparser
import logging
import requests
import socket
import requests.cookies
import xml.etree.ElementTree as ET
import urllib3
import os

# Disable SSL warnings (since JioFiber uses a self-signed certificate)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
HASH_MULTIPLIER = 33
DEFAULT_JIOFIBER_HOSTNAME = "jiofiber.local.html"
DEFAULT_JIOFIBER_HTTPS_PORT = 8443
DEFAULT_CONFIG_FLAG_FILENAME = "JFC_CONFIG_DONE"
DEFAULT_MICROSIP_CONFIG = """
[Settings]
accountId=1
singleMode=1
ringingSound=ringing.wav
volumeRing=100
audioRingDevice=""
audioOutputDevice=""
audioInputDevice=""
micAmplification=0
swLevelAdjustment=0
audioCodecs=AMR-WB/16000/1 AMR/8000/1
VAD=0
EC=0
forceCodec=0
opusStereo=0
disableMessaging=0
disableVideo=0
videoCaptureDevice=""
videoCodec=
videoH264=1
videoH263=1
videoVP8=1
videoVP9=1
videoBitrate=512
rport=1
sourcePort=0
rtpPortMin=52000
rtpPortMax=52200
dnsSrvNs=
dnsSrv=0
STUN=
enableSTUN=0
recordingPath=Recordings
recordingFormat=mp3
autoRecording=1
recordingButton=1
DTMFMethod=0
autoAnswer=button
autoAnswerDelay=0
autoAnswerNumber=
forwarding=
forwardingNumber=
forwardingDelay=0
denyIncoming=button
usersDirectory=
defaultAction=
enableMediaButtons=0
headsetSupport=0
localDTMF=1
enableLog=0
bringToFrontOnIncoming=1
enableLocalAccount=0
randomAnswerBox=0
callWaiting=1
updatesInterval=never
checkUpdatesTime=1737295400
noResize=0
userAgent=
autoHangUpTime=0
maxConcurrentCalls=0
noIgnoreCall=0
cmdOutgoingCall=
cmdIncomingCall=
cmdCallRing=
cmdCallAnswer=
cmdCallAnswerVideo=
cmdCallBusy=
cmdCallStart=
cmdCallEnd=
minimized=0
silent=0
portKnockerHost=
portKnockerPorts=
mainX=194
mainY=88
mainW=748
mainH=528
messagesX=986
messagesY=288
messagesW=550
messagesH=528
ringinX=0
ringinY=0
callsWidth0=0
callsWidth1=0
callsWidth2=0
callsWidth3=0
callsWidth4=0
callsWidth5=0
contactsWidth0=0
contactsWidth1=0
contactsWidth2=0
volumeOutput=100
volumeInput=100
activeTab=0
AA=0
AC=0
DND=0
alwaysOnTop=0
multiMonitor=0
enableShortcuts=0
shortcutsBottom=0
lastCallNumber=01234567890
lastCallHasVideo=1
callsLastKey=36
[Account1]
label=+910000000000@xx.wln.ims.jio.com
server=xx.wln.ims.jio.com
proxy=192.168.29.1:5068
domain=192.168.29.1:5068
username=+910000000000@xx.wln.ims.jio.com
password=xxxxxxx
authID=910000000000@xx.wln.ims.jio.com
displayName=
dialingPrefix=
dialPlan=
hideCID=0
voicemailNumber=
transport=tls
publicAddr=
SRTP=
registerRefresh=86400
keepAlive=15
publish=0
ICE=0
allowRewrite=0
disableSessionTimer=0
[Calls]

[Dialed]

"""


class RawResponse:
    """A response-like object to mimic `requests.Response`."""

    def __init__(self, status_code, headers, body, raw_data):
        self.status_code = status_code
        self.headers = headers
        self.text = body.decode(errors='replace')
        self.raw = raw_data

    def __str__(self):
        return {
            "status_code": self.status_code,
            "headers": self.headers,
            "text": self.text,
            "raw": self.raw,
        }.__str__()


def raw_http_request(url, method="GET", headers=None, ignore_ssl=True):
    """Performs a raw HTTP(S) request and returns a custom response-like object."""
    parsed_url = urlparse(url)
    hostname = parsed_url.hostname
    port = parsed_url.port or (443 if parsed_url.scheme == "https" else 80)
    path = parsed_url.path or "/"
    query = f"?{parsed_url.query}" if parsed_url.query else ""
    full_path = path + query

    # Create a secure or plain socket
    if parsed_url.scheme == "https":
        if ignore_ssl:
            # Create an insecure SSL context
            context = create_default_context()
            context.check_hostname = False
            context.verify_mode = CERT_NONE
        else:
            context = create_default_context()
        sock = context.wrap_socket(socket.create_connection(
            (hostname, port)), server_hostname=hostname)
    else:
        sock = socket.create_connection((hostname, port))

    try:
        # Construct the HTTP request
        request_lines = [
            f"{method} {full_path} HTTP/1.1",
            f"Host: {hostname}",
            "Connection: close",
        ]
        if headers:
            request_lines.extend(
                f"{key}: {value}" for key, value in headers.items())
        request_lines.append("")  # Empty line to separate headers and body
        request_lines.append("")  # Ensure end of request
        request_data = "\r\n".join(request_lines)
        sock.sendall(request_data.encode())

        # Read the raw response
        response_data = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response_data += chunk

        # Parse response into headers and body
        headers, body = response_data.split(b"\r\n\r\n", 1)
        status_line, *header_lines = headers.split(b"\r\n")
        status_code = int(status_line.split(b" ")[1])
        parsed_headers = {line.split(b":", 1)[0].decode(): line.split(b":", 1)[1].strip().decode()
                          for line in header_lines if b":" in line}

        # Return a response-like object
        return RawResponse(status_code, parsed_headers, body, response_data)

    finally:
        sock.close()


def setup_logger(log_level: int):
    """Set up the logger with the specified log level."""
    log_levels = {
        1: logging.CRITICAL,
        2: logging.ERROR,
        3: logging.WARNING,
        4: logging.INFO,
        5: logging.DEBUG,
    }

    # Default to INFO if the provided level is invalid
    level = log_levels.get(log_level, logging.INFO)

    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    requests_log = logging.getLogger("requests.packages.urllib3")
    requests_log.setLevel(log_level)
    requests_log.propagate = True


def ask_confirmation(prompt: str) -> bool:
    """
    Ask the user for confirmation (Y/N) and return the response.

    Parameters:
        prompt (str): The prompt to display to the user.

    Returns:
        bool: True if the user confirms, False otherwise.
    """

    response = input(
        f"{prompt}\nDo you want to continue? (y/n): ").strip().lower()
    return response == 'y' or response == 'yes'


def calculate_hash(hash: int, key: bytearray) -> int:
    """
    Calculates a hash value based on a given key.

    Parameters:
        hash (int): The initial hash value.
        key (bytearray): The input key to hash.

    Returns:
        int: The calculated hash value.
    """

    for byte in key:
        hash = (hash * HASH_MULTIPLIER) + byte
        hash = hash & 0xFFFFFFFF  # Ensure the hash stays within 32 bits
    return hash


def convert_to_hex(hval: int) -> str:
    """
    Converts a hash value to a hexadecimal string.

    Parameters:
        hval (int): The input hash value.

    Returns:
        str: The hexadecimal string representation of the hash value.
    """

    # Convert hash to hex and ensure it's 8 characters (padded if necessary)
    hex_val = "{:08X}".format(hval)
    # Reverse the byte order (little-endian to match C++ output)
    return ''.join(reversed([hex_val[i:i+2] for i in range(0, len(hex_val), 2)]))


def get_hash(string: str) -> int:
    """
    Get the hash value of the given string.

    Parameters:
        string (str): The input string to hash.

    Returns:
        int: The hash value of the given string.
    """

    # Calculate the hash value
    return calculate_hash(0, bytearray(string, 'utf-8'))


def hex_to_mac(hex_string: str) -> str:
    """
    Converts a hexadecimal string into a MAC address format.

    Parameters:
        hex_string (str): The input hexadecimal string.

    Returns:
        str: The formatted MAC address.
    """

    # Ensure the hex string is even-length and pad with leading zeros if needed
    hex_string = hex_string.zfill(12).lower()

    # Format the MAC address by grouping every two characters with a colon
    mac_address = ":".join(hex_string[i:i+2]
                           for i in range(0, len(hex_string), 2))
    return mac_address


def get_mac_address() -> str:
    """
    Get the MAC address of the current machine based on its hostname.

    Returns:
        str: The MAC address of the current machine based on its hostname.
    """

    # Get the hostname hash and convert it to a hexadecimal string
    hostname = socket.gethostname()
    logging.debug(f"Hostname: {hostname}")
    hval = get_hash(hostname)
    logging.debug(f"Hostname hash: {hval}")
    hval_hex = convert_to_hex(hval)
    logging.debug(f"Hostname hash (hex): {hval_hex}")

    # Convert the hexadecimal string to a MAC address format
    mac_address = hex_to_mac(hval_hex)
    logging.debug(f"Hostname to MAC: {mac_address}")
    return mac_address


def check_domain(domain: str) -> str | None:
    """
    Get domain automatically

    Parameters:
        domain (str): The JioFiber domain to check.

    Returns:
        str: The domain if it is valid under DNS, else None.
    """

    # Check if the hostname is valid under DNS
    try:
        ip = socket.gethostbyname(domain)
        logging.debug(f"Found JioFiber domain: {domain} ({ip})")
        return domain
    except socket.gaierror:
        # If the hostname is not valid, return None
        logging.warning(f"JioFiber domain not found: {domain}")
        return None


def ims_request(
        domain: str,
        port: int,
        hostname: str,
        mac: str,
        add_req: bool = False,
        no_otp: bool = False
) -> requests.Response | RawResponse:
    """ Send an IMS request to the JioFiber SIP server.

    Parameters:
        domain (str): The JioFiber domain to send the request to.
        port (int): The port to use for the request.
        hostname (str): The hostname of the device.
        mac (str): The MAC address of the device.
        add_req (bool): Whether to send an additional request to add the device.

    Returns:
        requests.Response | RawResponse: The response from the IMS request.
    """

    url = f"https://{domain}:{port}/"

    get_params = {
        "terminal_sw_version": "RCSAndrd",
        "terminal_vendor": hostname,
        "terminal_model": hostname,
        "SMS_port": 0,
        "act_type": "volatile",
        "IMSI": "",
        "msisdn": "",
        "IMEI": "",
        "vers": 0,
        "token": "",
        "rcs_state": 0,
        "rcs_version": "5.1B",
        "rcs_profile": "joyn_blackbird",
        "client_vendor": "JUIC",
        "default_sms_app": 2,
        "default_vvm_app": 0,
        "device_type": "vvm",
        "client_version": "JSEAndrd-1.0",
        "mac_address": mac,
        "alias": hostname,
        "nwk_intf": "eth" if no_otp else "wifi"
    }

    if add_req:
        get_params["op_type"] = "add"

        get_url = f"{url}?"
        for key, value in get_params.items():
            get_url += f"{key}={value}&"
        return raw_http_request(get_url, method="GET", ignore_ssl=True)

    # Send the IMS request
    return requests.get(url, params=get_params, verify=False)


def otp_verify(domain: str, port: int, otp: int, cookies_str: str):
    """ Verify the OTP sent to the user's mobile number.

    Parameters:
        domain (str): The JioFiber domain to send the request to.
        port (int): The port to use for the request.
        otp (int): The OTP to verify.
        cookies_str (str): The cookies string from the previous response.

    Returns:
        requests.Response: The response from the OTP verification request.
    """

    url = f"https://{domain}:{port}/"

    get_params = {
        "OTP": otp,
    }

    cookies = requests.cookies.cookiejar_from_dict(
        {cookie.split("=")[0]: cookie.split("=")[1]
         for cookie in cookies_str.split("; ")}
    )

    # Send the IMS request
    return requests.get(url, params=get_params, cookies=cookies, verify=False)


def ims_register(domain: str, port: int, hostname: str, mac: str) -> bool:
    """ Register the device on the JioFiber SIP server.

    Parameters:
        domain (str): The JioFiber domain to send the request to.
        port (int): The port to use for the request.
        hostname (str): The hostname of the device.
        mac (str): The MAC address of the device.

    Returns:
        bool: True if the device was registered successfully, False otherwise.
    """

    logging.info("Registering the device on JioFiber SIP...")
    if not ask_confirmation("An OTP will be sent to your registered mobile number."):
        logging.info("Registration cancelled by the user.")
        exit(0)

    response = ims_request(domain, port, hostname, mac, add_req=True)
    logging.debug(response)
    if response.status_code != 200:
        logging.error(
            f"Registration request failed with status code: {
                response.status_code}"
        )
        logging.error(f"Registration response: {response.text}")
        logging.info("Failed to register the device on JioFiber SIP!")
        return False

    mobile = response.headers.get("x-amn")
    logging.info(f"OTP was sent successfully to {mobile}!")

    otp_attempts = 0

    while otp_attempts < 3:
        otp = int(input("Enter the OTP: "))

        response = otp_verify(
            domain, port, otp, response.headers.get("Set-Cookie"))
        if response.status_code != 200:
            logging.error(
                f"OTP verification failed with status code: {
                    response.status_code}"
            )
            logging.error(f"OTP verification response: {response.text}")
            logging.info("Failed to verify the OTP!")
            logging.info("Try again!")
            otp_attempts += 1
        else:
            logging.info("OTP verification successful!")
            logging.info("Device registered successfully!")
            return True


def parse_sip_config(
        sip_config: ET.Element,
        config_str: str = DEFAULT_MICROSIP_CONFIG,
        jiofiber_hostname: str = DEFAULT_JIOFIBER_HOSTNAME
):
    """ Parse the SIP configuration XML and save it to microsip.ini.

    Parameters:
        config (ET.Element): The root element of the SIP configuration XML.
    """

    params_to_extract = [
        "realm",
        "username",
        "userpwd",
        "home_network_domain_name",
        "address",
        "private_user_identity",
        "public_user_identity"
    ]

    # Extract the values
    extracted_values = {}
    for parm in sip_config.findall(".//parm"):
        name = parm.attrib.get("name")
        value = parm.attrib.get("value")
        if name in params_to_extract:
            extracted_values[name] = value

    logging.debug("Extracted SIP Configuration:")
    for key, value in extracted_values.items():
        logging.debug(f"{key}: {value}")

    config = configparser.ConfigParser()

    config.read_string(config_str)

    config.set("Account1", "label", "JioFiber SIP")
    config.set("Account1", "server",
               extracted_values["home_network_domain_name"])
    config.set("Account1", "proxy", extracted_values["address"])
    config.set("Account1", "domain", extracted_values["address"])
    config.set("Account1", "username", f"+{extracted_values["username"]}")
    config.set("Account1", "password", extracted_values["userpwd"])
    config.set("Account1", "authID", extracted_values["username"])
    config.set("Account1", "proxy", f"{jiofiber_hostname}:5068")
    config.set("Account1", "domain", f"{jiofiber_hostname}:5068")

    with open(os.path.join(SCRIPT_DIR, "microsip.ini"), "w") as configfile:
        config.write(configfile)

    logging.info("SIP Configuration saved to microsip.ini!")
    logging.info("Account Saved as JioFiber SIP!")
    logging.info("You can now use the configuration in MicroSIP.")
    logging.info(
        "You may need to restart MicroSIP for the changes to take effect.")
    logging.info("Thank you for using JioFiber SIP Configuration Tool!")
    print("-"*80)
    print("Follow: https://github.com/JFC-Group for updates regarding JioFiber and AirFiber!")
    print("Follow: https://github.com/itsyourap")
    print("-"*80)
    with open(os.path.join(SCRIPT_DIR, DEFAULT_CONFIG_FLAG_FILENAME), "w") as flagfile:
        flagfile.write("1")
    print("Configuration Done! Please restart MicroSIP to apply the changes.")


def main(no_otp: bool = False):
    jiofiber_domain = check_domain(DEFAULT_JIOFIBER_HOSTNAME)
    while jiofiber_domain is None:
        logging.info("Couldn't find JioFiber domain/IP!")
        logging.info("Please enter the JioFiber domain/IP manually.")
        input_domain = input("Enter the JioFiber domain/IP: ")
        jiofiber_domain = check_domain(input_domain)

    hostname = socket.gethostname()
    mac = get_mac_address()

    try_config_count = 0
    sip_config_success = False

    while try_config_count < 3:
        sip_configuration_response = ims_request(
            jiofiber_domain, DEFAULT_JIOFIBER_HTTPS_PORT, hostname, mac, add_req=False, no_otp=no_otp)
        if sip_configuration_response.status_code != 200:
            logging.warning(
                f"SIP Configuration request failed with status code: {
                    sip_configuration_response.status_code
                }"
            )
            logging.info(
                f"Hostname: {hostname} isn't registered on JioFiber SIP yet!"
            )
            if not ims_register(jiofiber_domain, DEFAULT_JIOFIBER_HTTPS_PORT, hostname, mac):
                logging.error("Failed to register the device on JioFiber SIP!")
            else:
                try_config_count += 1
        else:
            sip_config_success = True
            break

    if not sip_config_success:
        logging.error("Failed to get SIP Configuration!")
        return

    logging.debug(
        f"SIP Configuration request successful with status code: {
            sip_configuration_response.status_code
        }"
    )

    logging.debug(
        f"SIP Configuration response: \n -------- BEGIN RESPONSE -------- \n {
            sip_configuration_response.text
        }\n -------- END RESPONSE --------"
    )
    logging.info("Received SIP Configuration Successfully!")

    root = ET.fromstring(sip_configuration_response.text)
    parse_sip_config(sip_config=root, jiofiber_hostname=jiofiber_domain)


if __name__ == "__main__":
    print("JioFiber SIP Configuration Tool by JFC-Group")
    print("Author: Ankan Pal (@itsyourap)")
    print("-"*80)
    print("This tool helps you configure MicroSIP with your JioFiber SIP settings.")
    print("-"*80)

    parser = argparse.ArgumentParser(description="Set the logger level.")
    parser.add_argument(
        '-n',
        '--no-otp',
        help="Configure without OTP verification",
        action='store_true'
    )
    parser.add_argument(
        '-l',
        '--log-level',
        help="Log level (1 for CRITICAL, 2 for ERROR, 3 for WARNING, 4 for INFO, 5 for DEBUG)",
        type=int,
        default=4,
    )

    args = parser.parse_args()
    setup_logger(args.log_level)

    main(args.no_otp)
    input("Press Enter to exit...")
