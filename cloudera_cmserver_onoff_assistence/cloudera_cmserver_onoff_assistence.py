from __future__ import print_function
import os
import sys
import argparse
import logging
import time
import socket
import ConfigParser

logging.basicConfig(format='%(asctime)s %(name)-12s %(levelname)-8s %(message)s',
                    datefmt='%m-%d %H:%M:%S')
formatter = logging.Formatter(
    '%(asctime)s %(name)-12s %(levelname)-8s %(message)s', '%m-%d %H:%M:%S')
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

def load_properties(filepath, sep='=', comment_char='#'):
    """
    Read the file passed as parameter as a properties file.
    """
    props = {}
    with open(filepath, "rt") as f:
        for line in f:
            l = line.strip()
            if l and not l.startswith(comment_char):
                key_value = l.split(sep)
                key = key_value[0].strip()
                value = sep.join(key_value[1:]).strip().strip('"')
                props[key] = value
    return props

def is_postgres_running(host):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    result = sock.connect_ex((host, 5432))
    is_open = False
    if result == 0:
        is_open = True
    sock.close()
    return is_open

def restart_cm_server():
    os.system("service cloudera-scm-server restart")

def stop_cm_server():
    os.system("service cloudera-scm-server stop")

def main():
    parser = argparse.ArgumentParser(
        description='Cloudera Manager Server OFF/ON assistance\nUsed to start and stop a Cloudera Manager instance in a clean way.\nCommand line arguments overrides values defined in config.ini')
    # Add arguments
    parser.add_argument(
        '--db-host', type=str, help='Database host (e.g. "127.0.0.1"). If not specified, it will be read from Cloudera Manager Server config file (db.properties)', required=False)
    parser.add_argument(
        '--db-config-path', type=str, help='Path for the Cloudera Manager Server db.properties file; will be used to retrieve the DB host. Default: /etc/cloudera-scm-server/db.properties', required=False, default='/etc/cloudera-scm-server/db.properties')
    parser.add_argument(
        '--action', type=str, help='Which action to perform (restart, stop)', choices=['restart', 'stop'], required=True)
    parser.add_argument(
        '--max-wait', type=int, help='Max time (in seconds) to wait for DB to become available when starting the cluster. Default: 3600', required=False, default=3600)
    parser.add_argument(
        '--log-file', type=str, help='Path for the log file', required=False)
    parser.add_argument(
        '--config-file', type=str, help='Path for the config.ini file. Default: ./config.ini', required=False, default='./config.ini')
    # Array for all arguments passed to script
    args = parser.parse_args()

    # parse the configuration file
    config = ConfigParser.ConfigParser()
    config.read(args.config_file)
    db_host = config.get("Main", "db_host")
    db_config_path = config.get("Main", "db_config_path")

    log_file = None
    maxbytes = 20000000

    # Override config values from commandline arguments
    if args.db_host is not None:
        db_host = args.db_host
    if args.db_config_path is not None:
        db_config_path = args.db_config_path
    if args.log_file is not None:
        log_file = args.log_file
    action = args.action
    max_wait = args.max_wait

    if log_file is not None:
        handler = RotatingFileHandler(
            args.log_file, maxBytes=maxbytes, backupCount=5)
        logger.addHandler(handler)

    if action == "restart":
        # if DB was not explicitly provided, get it from the db.properties file
        if db_host is None:
            props = load_properties(db_config_path)
            db_host = props["com.cloudera.cmf.db.host"]

        # wait for the DB to come online
        start_time = time.time()
        while True:
            now = time.time()
            if is_postgres_running(db_host):
                break
            elif now - start_time > max_wait:
                logger.error("Postgres seem to not be reachable; trying to start CMS anyway")
                break
            logger.debug("DB not available. Sleeping 15 seconds and retrying...")
            time.sleep(15)

        restart_cm_server()
    elif action == "stop":
        stop_cm_server()
    else:
        logger.error("Unknown action: {0}".format(action))


if __name__ == "__main__":
    main()
