from __future__ import print_function
import os
import sys
import argparse
import logging
import time
import ConfigParser
import requests
from requests.auth import HTTPDigestAuth

logging.basicConfig(format='%(asctime)s %(name)-12s %(levelname)-8s %(message)s',
                    datefmt='%m-%d %H:%M:%S')
formatter = logging.Formatter(
    '%(asctime)s %(name)-12s %(levelname)-8s %(message)s', '%m-%d %H:%M:%S')
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

script_path = os.path.dirname(os.path.realpath(__file__))

# api example: http://myhost.example.com:7180/api/v10/clusters/cluster/commands/restart
API_ROOT = "/api"
API_VERSION = "v10"

def is_cm_available(base_url, auth):
    try:
        full_url = base_url + "/tools/echo"
        r = requests.get(full_url, auth=auth)
        if r.ok:
            return True
        elif r.status_code == 401:
            logger.error("Server replied \"401 Unauthorized\"; check your username and password.")
    except ConnectionError as e:
        return False

def get_hosts(base_url, auth):
    full_url = base_url + "/hosts"
    r = requests.get(full_url, auth=auth)
    if r.ok:
        items = r["items"]
        hosts = []
        for item in items:
            if item["commissionState"] == "COMMISSIONED":
                hosts.append(item["hostId"])
        return hosts
    else:
        # If response code is not ok (200), print the resulting http error code with description
        r.raise_for_status()


def get_host_availability(base_url, auth, host_id):
    full_url = base_url + "/hosts/{0}".format(host_id)
    r = requests.get(full_url, auth=auth)
    if r.ok:
        return host_id, r["ipAddress"], r["hostname"], r["healthSummary"]
    else:
        r.raise_for_status()


def get_unavailable_hosts(base_url, auth, hosts):
    results = []
    for host_id in hosts:
        result = get_host_availability(base_url, auth, host_id)
        if result[3] == "NOT_AVAILABLE":
            results.append(result)
    return results


def get_cm_host_from_config(cm_config_path):
    cm_config = ConfigParser.ConfigParser()
    cm_config.read(cm_config_path)
    cm_host = cm_config.get("General", "server_host")
    logger.debug("CM Server host read from configuration: {0}".format(cm_host))
    return cm_host


def restart_cm_services(base_url, auth):
    full_url = base_url + "/cm/service/commands/restart"
    r = requests.post(full_url, auth=auth)
    if r.ok:
        logger.info("CM Services restarted")
    else:
        r.raise_for_status()


def restart_cluster(base_url, auth, cluster):
    full_url = base_url + "/clusters/{0}/commands/restart".format(cluster)
    r = requests.post(full_url, auth=auth)
    if r.ok:
        logger.inf("Cluster \"{0}\" restarted".format(cluster))
    else:
        r.raise_for_status()


def restart_all_clusters(base_url, auth):
    full_url = base_url + "/clusters"
    r = requests.get(full_url, auth=auth)
    if r.ok:
        for item in r["items"]:
            restart_cluster(base_url, auth, item["name"])
    else:
        r.raise_for_status()


def stop_cm_services(base_url, auth):
    full_url = base_url + "/cm/service/commands/stop"
    r = requests.post(full_url, auth=auth)
    if r.ok:
        logger.info("CM Services stopped")
    else:
        r.raise_for_status()


def stop_cluster(base_url, auth, cluster):
    full_url = base_url + "/clusters/{0}/commands/stop".format(cluster)
    r = requests.post(full_url, auth=auth)
    if r.ok:
        logger.inf("Cluster \"{0}\" stopped".format(cluster))
    else:
        r.raise_for_status()


def stop_all_clusters(base_url, auth):
    full_url = base_url + "/clusters"
    r = requests.get(full_url, auth=auth)
    if r.ok:
        for item in r["items"]:
            restart_cluster(base_url, auth, item["name"])
    else:
        r.raise_for_status()


def main():

    parser = argparse.ArgumentParser(
        description='Cloudera cluster OFF/ON assistance\nUsed to start and stop a Cloudera cluster in the cleanest possible way.\nCommand line arguments overrides values defined in config.ini')
    # Add arguments
    parser.add_argument(
        '--cm-host', type=str, help='Cloudera Manager host (e.g. "127.0.0.1"). If not specified, it will be read from Cloudera Manager agent config file', required=False)
    parser.add_argument(
        '--cm-port', type=int, help='Cloudera Manager port', required=False)
    parser.add_argument(
        '--cm-user', type=str, help='Cloudera Manager username (e.g. "admin", although you should not use the admin user but an OPERATOR user)', required=False)
    parser.add_argument(
        '--cm-pass', type=str, help='Cloudera Manager user\'s password', required=False)
    parser.add_argument(
        '--cm-config-path', type=str, help='Path for the Cloudera Manager Agent config file; will be used to retrieve the CM host. Default: /etc/cloudera-scm-agent/config.ini', required=False, default='/etc/cloudera-scm-agent/config.ini')
    parser.add_argument(
        '--action', type=str, help='Which action to perform (restart, stop)', choices=['restart', 'stop'], required=True)
    parser.add_argument(
        '--max-wait', type=int, help='Max time (in seconds) to wait for hosts to become available when starting the cluster. Default: 300', required=False, default=300)
    parser.add_argument(
        '--log-file', type=str, help='Path for the log file', required=False)
    parser.add_argument(
        '--config-file', type=str, help='Path for the config.ini file. Default: config.ini in the same path as the script', required=False)
    # Array for all arguments passed to script
    args = parser.parse_args()

    # parse the configuration file
    config = ConfigParser.ConfigParser()
    if args.config_file is not None:
        config.read(args.config_file)
    else:
        config.read(os.path.join(script_path, "config.ini"))
    cm_host = config.get("Main", "cm_host")
    cm_port = config.get("Main", "cm_port")
    cm_user = config.get("Main", "cm_user")
    cm_pass = config.get("Main", "cm_pass")
    cm_config_path = config.get("Main", "cm_config_path")

    log_file = None
    maxbytes = 20000000

    # Override config values from commandline arguments
    if args.cm_host is not None:
        cm_host = args.cm_host
    if args.cm_port is not None:
        cm_port = args.cm_port
    if args.cm_user is not None:
        cm_user = args.cm_user
    if args.cm_pass is not None:
        cm_pass = args.cm_pass
    if args.cm_config_path is not None:
        cm_config_path = args.cm_config_path
    if args.log_file is not None:
        log_file = args.log_file
    action = args.action
    max_wait = args.max_wait

    if log_file is not None:
        handler = RotatingFileHandler(
            args.log_file, maxBytes=maxbytes, backupCount=5)
        logger.addHandler(handler)

    if not cm_host:
        cm_host = get_cm_host_from_config(cm_config_path)

    url = "http://{0}:{1}{2}/{3}".format(cm_host,
                                         cm_port, API_ROOT, API_VERSION)
    auth = HTTPDigestAuth(cm_user, cm_pass)

    # Wait for CM Server to come online
    start_time = time.time()
    while True:
        now = time.time()
        if is_cm_available(url, auth):
            logger.info("CM Server running at {0} is online".format(url))
            break
        if now - start_time > max_wait:
            logger.error("Error; CM Server didn't become available in {0} seconds".format(max_wait))
            exit(1)
        logger.info("CM Server not available; sleeping 15 seconds and retrying...")
        time.sleep(15)

    if action == "restart":
        # Wait for all Cluster hosts to be online
        start_time = time.time()
        hosts = get_hosts(url, auth)
        while True:
            unavail_hosts = get_unavailable_hosts(url, auth, hosts)
            now = time.time()
            if len(unavail_hosts) == 0 or now - start_time > max_wait:
                if len(unavail_hosts) > 0:
                    logger.warn(
                        "There are unavailable hosts, but {0} seconds passed; starting anyway.\nUnavailable hosts:".format(max_wait))
                    for unavail_host in unavail_hosts:
                        logger.warn(unavail_host)
                break
            logger.info("There are currently {0} hosts unavailable. Sleeping 15 seconds and retrying...".format(
                len(unavail_hosts)))
            time.sleep(15)

        # Restart the CM Server and Services
        restart_all_clusters(url, auth)
        restart_cm_services(url, auth)
    elif action == "stop":
        stop_all_clusters(url, auth)
        stop_cm_services(url, auth)
    else:
        logger.error("Unknown action: {0}".format(action))


if __name__ == "__main__":
    main()
