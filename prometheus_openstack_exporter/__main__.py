import argparse
import logging
from os import path

import prometheus_client
import yaml

from .exporter import DataGatherer, log

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        usage=__doc__,
        description="Prometheus OpenStack exporter",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument(
        "config_file",
        nargs="?",
        help="Configuration file path",
        default="/etc/prometheus/prometheus-openstack-exporter.yaml",
        type=argparse.FileType("r"),
    )
    cli_args = parser.parse_args()

    log.setLevel(level=logging.DEBUG)
    for logsock in ("/dev/log", "/var/run/syslog"):
        if path.exists(logsock):
            log.addHandler(logging.handlers.SysLogHandler(address=logsock))
            break
    else:
        log.addHandler(logging.StreamHandler())

    config = yaml.safe_load(cli_args.config_file.read())
    numeric_log_level = getattr(logging, config.get("log_level", "INFO").upper(), None)
    if not isinstance(numeric_log_level, int):
        raise ValueError("Invalid log level: %s" % config.get("log_level"))
    log.setLevel(numeric_log_level)

    prometheus_client.start_http_server(config.get("listen_port", 9183))
    data_gatherer = DataGatherer(config=config)
    data_gatherer.run()
