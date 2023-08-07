#! /usr/bin/python3

import argparse
import copy
import http.client
import re
import prometheus_client as pclient
import prometheus_client.core
import socket
import threading
import time
import xml.etree.ElementTree as ET

from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn

VERSION = '0.6'
PROM_PORT = 9310
PROM_ADDRESS = '::'
INFO_PORT = 22112
INFO_ADDRESS = 'localhost'

DOOR_METRICS = ['load']
DOMAIN_METRICS = ['event_queue_size', 'thread_count']
POOL_METRICS = [
    # pools/pool
    'heartbeat_seconds', 'enabled', 'read_only',
    # pools/pool/queues/?queue-names/queue
    'active', 'queued',
    # pools/pool/space
    'total_bytes', 'precious_bytes', 'removable_bytes', 'used_bytes', 'free_bytes',
    'gap_bytes', 'LRU_seconds', 'break_even',
]
POOLGROUP_METRICS = [
    # poolgroups/poolgroup
    'resilient',
    # poolgroups/poolgroup/space
    'total_bytes', 'precious_bytes', 'removable_bytes', 'used_bytes', 'free_bytes',
]
LINK_METRICS = [
    # links/link/space
    'total_bytes', 'precious_bytes', 'removable_bytes', 'used_bytes', 'free_bytes',
    # links/link/prefs
    'cache', 'read', 'write', 'p2p',
]
LINKGROUP_METRICS = [
    # linkgroups/linkgroup/space
    'total_bytes', 'reserved_bytes', 'available_bytes', 'used_bytes', 'free_bytes',
]

METRIC_GROUPS = [
    DOOR_METRICS,
    DOMAIN_METRICS,
    POOL_METRICS,
    POOLGROUP_METRICS,
    LINK_METRICS,
    LINKGROUP_METRICS,
]
BYTES_METRICS = set(m[:-6] for g in METRIC_GROUPS for m in g if m.endswith('_bytes'))

def start_http6_server(port, addr=''):
    """Starts an HTTP server for prometheus metrics as a daemon thread"""
    class ThreadingSimpleServer(ThreadingMixIn, HTTPServer):
        address_family = socket.AF_INET6
    class PrometheusMetricsServer(threading.Thread):
        def run(self):
            httpd = ThreadingSimpleServer((addr, port), pclient.MetricsHandler)
            httpd.serve_forever()
    t = PrometheusMetricsServer()
    t.daemon = True
    t.start()


def get_namespace(element):
    m = re.match('\{.*\}', element.tag)
    return m.group(0)


def get_short_tag(element):
    m = re.match('(\{.*\})?(.*)', element.tag)
    return m.group(2)


class ExportTag(object):
    def __init__(self, name, prefix, default=None, include=[], exclude=[], init_func=None, filter_func=None):
        self.name = name
        self.prefix = prefix
        self.default = default
        self.include = include
        self.exclude = exclude
        self._init_func = init_func
        self._filter_func = filter_func

    def collect_init(self, element):
        if self._init_func:
            self.data = self._init_func(element)

    def collect_metric(self, name, labels):
        if self.default is None:
            return True
        if name in self.include:
            ok = True
        elif name in self.exclude:
            ok = False
        else:
            ok = self.default
        if ok and self._filter_func:
            return self._filter_func(self.data, labels)
        return ok

    @staticmethod
    def DomainInit(element):
        valid_cells = []
        for routing in element:
            if get_short_tag(routing) == 'routing':
                for route in routing:
                    if get_short_tag(route) == 'local':
                        for cell in route:
                            if get_short_tag(cell) == 'cellref':
                                name = cell.attrib.get('name')
                                valid_cells.append(('cell_name', name))
        return valid_cells

    @staticmethod
    def DomainFilter(data, labels):
        for d in data:
            if d in labels:
                return True
        return False

class DcacheCollector(object):
    ExportTags = [
        ExportTag('doors', 'door', False, DOOR_METRICS, []),
        ExportTag('domains', 'domain', False, DOMAIN_METRICS, [],
                  ExportTag.DomainInit, ExportTag.DomainFilter),
        ExportTag('pools', 'pool', False, POOL_METRICS, []),
        ExportTag('poolgroups', 'poolgroup', False, POOLGROUP_METRICS, []),
        ExportTag('links', 'link', False, LINK_METRICS, []),
        ExportTag('linkgroups', 'linkgroup', False, LINKGROUP_METRICS, []),
    ]

    def __init__(self, host, port, cluster):
        self._info_host = host
        self._info_port = port
        self._cluster = cluster
        self._tree = None
        self._ns = None
        self._metrics = {}

    def _get_xml_tree(self):
        data = []
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((self._info_host, self._info_port))
        sock.settimeout(10)
        while True:
            d = sock.recv(1024)
            if not d:
                break
            data.append(d.decode('utf-8'))
        sock.close()
        text = ''.join(data)
        tree = ET.fromstring(text)
        return tree

    @staticmethod
    def _metric_transform(name):
        if name in BYTES_METRICS:
            return (name + '_bytes', (lambda x: x))
        if name == 'last-heartbeat':
            return ('heartbeat_seconds', (lambda x: x / 1000.0))
        return (name.replace('-', '_'), (lambda x: x))

    def _collect_metric(self, element, export, labels):
        tag = get_short_tag(element)
        if tag == 'metric':
            type = element.attrib.get('type')
            name, transform = self._metric_transform(element.get('name'))
            if export.collect_metric(name, labels):
                metric_name = 'dcache_{0}_{1}'.format(export.prefix, name)
                if type in ['float', 'integer', 'boolean']:
                    if type == 'boolean':
                        if element.text.strip() == 'true':
                            value = 1
                        else:
                            value = 0
                    elif type == 'float':
                        value = float(element.text)
                    else:
                        value = int(element.text)
                    value = transform(value)
                    if metric_name not in self._metrics:
                        self._metrics[metric_name] = pclient.core.GaugeMetricFamily(metric_name, '', labels=[ n for (n, v) in labels ])
                    self._metrics[metric_name].add_metric([ v for (n, v) in labels ], value)
        if tag == 'poolref':
            metric_name = 'dcache_{0}_pool_rel'.format(export.prefix)
            labels = copy.copy(labels)
            labels.append(('pool', element.attrib.get('name')))
            if not metric_name in self._metrics:
                self._metrics[metric_name] = pclient.core.GaugeMetricFamily(
                        metric_name, '', labels=[k for k, _ in labels])
            self._metrics[metric_name].add_metric([v for _, v in labels], 1)
        else:
            for child in element:
                l = copy.copy(labels)
                for n,v in element.attrib.items():
                    l.append( ('{0}_{1}'.format(tag, n), v) )
                self._collect_metric(child, export, l)

    def _collect_metrics_set(self, element, export):
        export.collect_init(element)
        if get_short_tag(element) == 'linkgroup':
            name = element.attrib.get('lgid')
        else:
            name = element.attrib.get('name')
            if '@' in name:
                name = name[:name.find('@')]
        labels = [ ('dcache_cluster', self._cluster), (export.prefix, name) ]
        for child in element:
            self._collect_metric(child, export, labels)

    def _collect_all_metrics(self):
        self._metrics = {}
        for export in DcacheCollector.ExportTags:
            elements = self._tree.findall('{0}{1}'.format(self._ns, export.name))
            if len(elements) > 0:
                for elem in elements[0]:
                    self._collect_metrics_set(elem, export)

    def collect(self):
        try:
            self._tree = self._get_xml_tree()
            self._ns = get_namespace(self._tree)
            self._collect_all_metrics()
            for metric_name in sorted(self._metrics.keys()):
                yield self._metrics[metric_name]
        except ConnectionRefusedError:
            pass


def create_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument('--metrics-port', dest='metrics_port', type=int, default=PROM_PORT, help='port to export metrics on')
    parser.add_argument('--metrics-address', dest='metrics_address', type=str, default=PROM_ADDRESS, help='address to export metrics on')
    parser.add_argument('-c', '--cluster', dest='cluster', type=str, default='dcache_cluster', help='cluster prometheus label')
    parser.add_argument('--info-port', dest='info_port', type=int, default=INFO_PORT, help='port to export metrics on')
    parser.add_argument('--info-address', dest='info_address', type=str, default=INFO_ADDRESS, help='address to export metrics on')
    return parser


def main():
    parser = create_parser()
    args = parser.parse_args()
    pclient.REGISTRY.register(DcacheCollector(args.info_address, args.info_port, args.cluster))
    start_http6_server(args.metrics_port, args.metrics_address)
    while True:
        time.sleep(10)


if __name__ == '__main__':
    main()
