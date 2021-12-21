import abc
import ast
import json
import logging.handlers
import traceback
from os import environ as env
from time import sleep, time

from cinderclient.v3 import client as cinder_client
from netaddr import IPRange
from neutronclient.v2_0 import client as neutron_client
from novaclient import client as nova_client
from prometheus_client.core import Gauge

log = logging.getLogger("poe-logger")

# define all metrics

# cinder metrics
cinder_quota_volume_disk_gigabytes = Gauge(
    "cinder_quota_volume_disk_gigabytes",
    "Cinder volume metric (GB)",
    ["cloud", "tenant", "type"],
)
cinder_quota_volume_disks = Gauge(
    "cinder_quota_volume_disks",
    "Cinder volume metric (number of volumes)",
    ["cloud", "tenant", "type"],
)

# neutron metrics
neutron_public_ip_usage = Gauge(
    "neutron_public_ip_usage",
    "Neutron floating IP and router IP usage statistics",
    ["cloud", "subnet_name", "tenant", "ip_type", "ip_status"],
)
neutron_net_size = Gauge(
    "neutron_net_size", "Neutron networks size", ["cloud", "network_name"]
)
# nova
nova_quota_cores = Gauge(
    "nova_quota_cores", "Nova cores metric", ["cloud", "tenant", "type"]
)
nova_quota_floating_ips = Gauge(
    "nova_quota_floating_ips",
    "Nova floating IP addresses (number)",
    ["cloud", "tenant", "type"],
)
nova_quota_instances = Gauge(
    "nova_quota_instances", "Nova instances (number)", ["cloud", "tenant", "type"]
)
nova_quota_ram_mbs = Gauge(
    "nova_quota_ram_mbs", "Nova RAM (MB)", ["cloud", "tenant", "type"]
)
nova_instances = Gauge(
    "nova_instances",
    "Nova instances metrics",
    ["cloud", "name", "tenant", "instance_state"],
)
nova_resources_ram_mbs = Gauge(
    "nova_resources_ram_mbs", "Nova RAM usage metric", ["cloud", "tenant"]
)
nova_resources_vcpus = Gauge(
    "nova_resources_vcpus", "Nova vCPU usage metric", ["cloud", "tenant"]
)
nova_resources_disk_gbs = Gauge(
    "nova_resources_disk_gbs", "Nova disk usage metric", ["cloud", "tenant"]
)

nova_hypervisor_labels = [
    "cloud",
    "hypervisor_hostname",
    "aggregate",
    "nova_service_status",
    "arch",
]
hypervisor_running_vms = Gauge(
    "hypervisor_running_vms",
    "Number of running VMs",
    nova_hypervisor_labels,
)
hypervisor_vcpus_total = Gauge(
    "hypervisor_vcpus_total", "Total number of vCPUs", nova_hypervisor_labels
)
hypervisor_vcpus_used = Gauge(
    "hypervisor_vcpus_used", "Number of used vCPUs", nova_hypervisor_labels
)
hypervisor_memory_mbs_total = Gauge(
    "hypervisor_memory_mbs_total",
    "Total amount of memory in MBs",
    nova_hypervisor_labels,
)
hypervisor_memory_mbs_used = Gauge(
    "hypervisor_memory_mbs_used", "Used memory in MBs", nova_hypervisor_labels
)
hypervisor_disk_gbs_total = Gauge(
    "hypervisor_disk_gbs_total",
    "Total amount of disk space in GBs",
    nova_hypervisor_labels,
)
hypervisor_disk_gbs_used = Gauge(
    "hypervisor_disk_gbs_used", "Used disk space in GBs", nova_hypervisor_labels
)
hypervisor_schedulable_instances = Gauge(
    "hypervisor_schedulable_instances",
    'Number of schedulable instances, see "schedulable_instance_size" option',
    nova_hypervisor_labels,
)
hypervisor_schedulable_instances_capacity = Gauge(
    "hypervisor_schedulable_instances_capacity",
    "Number of schedulable instances we have capacity for",
    nova_hypervisor_labels,
)
openstack_allocation_ratio = Gauge(
    "openstack_allocation_ratio", "Openstack overcommit ratios", ["cloud", "resource"]
)


def get_creds_dict(*names):
    """Get dictionary with cred envvars"""
    return {
        name: env["OS_%s" % name.upper()]
        for name in names
        if "OS_%s" % name.upper() in env
    }


def get_creds_list(*names):
    """Get list with cred envvars, error if not set"""
    return [env["OS_%s" % name.upper()] for name in names]


def get_clients():
    ks_version = int(env.get("OS_IDENTITY_API_VERSION", 2))
    if ks_version == 2:
        from keystoneclient.v2_0 import client as keystone_client

        # Legacy v2 env vars:
        # OS_USERNAME OS_PASSWORD OS_TENANT_NAME OS_AUTH_URL OS_REGION_NAME
        ks_creds = get_creds_dict(
            "username", "password", "tenant_name", "auth_url", "region_name"
        )
        cacert = env.get("OS_CACERT")
        if cacert:
            ks_creds["cacert"] = cacert
        nova_creds = [2] + get_creds_list(
            "username", "password", "tenant_name", "auth_url"
        )
        cinder_creds = get_creds_list("username", "password", "tenant_name", "auth_url")
        keystone = keystone_client.Client(**ks_creds)
        nova = nova_client.Client(*nova_creds, cacert=cacert)
        neutron = neutron_client.Client(**ks_creds)
        cinder = cinder_client.Client(*cinder_creds, cacert=cacert)

    elif ks_version == 3:
        from keystoneauth1.identity import v3
        from keystoneauth1 import session
        from keystoneclient.v3 import client

        # A little helper for the poor human trying to figure out which env vars
        # are needed, it worked for me (jjo) having:
        #  OS_USERNAME OS_PASSWORD OS_USER_DOMAIN_NAME OS_AUTH_URL
        #  OS_PROJECT_DOMAIN_NAME OS_PROJECT_DOMAIN_ID OS_PROJECT_ID OS_DOMAIN_NAME
        # Keystone needs domain creds for e.g. project list

        # project and project_domain are needed for listing projects
        ks_creds_domain = get_creds_dict(
            "username",
            "password",
            "user_domain_name",
            "auth_url",
            "project_domain_name",
            "project_name",
            "project_domain_id",
            "project_id",
        )
        # Need non-domain creds to get full catalog
        ks_creds_admin = get_creds_dict(
            "username",
            "password",
            "user_domain_name",
            "auth_url",
            "project_domain_name",
            "project_name",
            "project_domain_id",
            "project_id",
        )
        auth_domain = v3.Password(**ks_creds_domain)
        auth_admin = v3.Password(**ks_creds_admin)
        # Need to pass in cacert separately
        verify = env.get("OS_CACERT")
        if verify is None:
            verify = True
        sess_domain = session.Session(auth=auth_domain, verify=verify)
        sess_admin = session.Session(auth=auth_admin, verify=verify)

        interface = env.get("OS_INTERFACE", "admin")

        # Keystone has not switched from interface to endpoint_type yet
        keystone = client.Client(session=sess_domain, interface=interface)
        nova = nova_client.Client(2, session=sess_admin, endpoint_type=interface)
        neutron = neutron_client.Client(session=sess_admin, endpoint_type=interface)
        cinder = cinder_client.Client(session=sess_admin, endpoint_type=interface)

    else:
        raise ValueError(f"Invalid OS_IDENTITY_API_VERSION={ks_version}")
    log.debug(f"Client setup done, keystone ver {ks_version}")
    return keystone, nova, neutron, cinder


class Collector(abc.ABC):
    def __init__(self, config: dict):
        self.config = config

    @abc.abstractmethod
    def collect(self, **kwargs):
        pass


class DataGatherer:
    """Periodically retrieve data from openstack in a separate thread,
    save as pickle to cache_file
    """

    def __init__(self, config: dict):
        self.config = config
        self.duration = 0
        self.refresh_interval = self.config.get("cache_refresh_interval", 900)
        self.cache_file = self.config["cache_file"]
        self.use_nova_volumes = self.config.get("use_nova_volumes", True)

        self.collectors = [
            Neutron(config=self.config),
            Nova(config=self.config),
            Cinder(config=self.config),
        ]

    def _get_keystone_tenants(self, keystone):
        try:
            tenants = [x._info for x in keystone.tenants.list()]
        except AttributeError:
            log.info("Error getting tenants.list, continue with projects.list")
            tenants = [x._info for x in keystone.projects.list()]
            log.debug("Number of projects: %s", len(tenants))
        return tenants

    def run(self):
        log.debug("Starting data gathering")
        while True:
            start_time = time()
            try:
                keystone, nova, neutron, cinder = get_clients()

                tenants = self._get_keystone_tenants(keystone=keystone)

                for collector in self.collectors:
                    collector.collect(
                        tenants=tenants,
                        nova=nova,
                        keystone=keystone,
                        cinder=cinder,
                        neutron=neutron,
                    )

            except Exception:
                # Ignore failures, we will try again after refresh_interval.
                # Most of them are termporary ie. connectivity problmes
                # To alert on stale cache use openstack_exporter_cache_age_seconds metric
                log.critical("Error getting stats: {}".format(traceback.format_exc()))

            self.duration = time() - start_time
            sleep(self.refresh_interval)


class Neutron(Collector):
    @staticmethod
    def _get_router_ip(uuid, ports):
        owner = "network:router_gateway"
        for port in ports:
            if port["device_id"] == uuid and port["device_owner"] == owner:
                if port["status"] == "ACTIVE" and port["fixed_ips"]:
                    return port["fixed_ips"][0]["ip_address"]

    def _get_floating_ips(self, floating_ips, network_map, tenant_map):
        ips = {}
        for ip in floating_ips:
            subnet = network_map[ip["floating_network_id"]]
            try:
                tenant = tenant_map[ip["tenant_id"]]
            except KeyError:
                tenant = "Unknown tenant ({})".format(ip["tenant_id"])
            key = (self.config["cloud"], subnet, tenant, "floatingip", ip["status"])
            if key in ips:
                ips[key] += 1
            else:
                ips[key] = 1
        return ips

    def _get_router_ips(self, routers, ports, tenant_map, network_map):
        ips = {}
        for r in routers:
            if self._get_router_ip(r["id"], ports=ports):
                if r["tenant_id"].startswith("<Tenant {"):
                    r["tenant_id"] = ast.literal_eval(r["tenant_id"][8:-1])["id"]
                try:
                    tenant = tenant_map[r["tenant_id"]]
                except KeyError:
                    tenant = "Unknown tenant ({})".format(r["tenant_id"])
                subnet = network_map[r["external_gateway_info"]["network_id"]]
                key = (self.config["cloud"], subnet, tenant, "routerip", r["status"])
                if key in ips:
                    ips[key] += 1
                else:
                    ips[key] = 1
        return ips

    def collect(self, tenants, neutron, **kwargs):
        floatingips = neutron.list_floatingips()["floatingips"]
        networks = neutron.list_networks()["networks"]
        ports = neutron.list_ports()["ports"]
        routers = neutron.list_routers()["routers"]
        subnets = neutron.list_subnets()["subnets"]

        tenant_map = {t["id"]: t["name"] for t in tenants}
        network_map = {n["id"]: n["name"] for n in networks}
        subnet_map = {
            n["id"]: {"name": n["name"], "pool": n["allocation_pools"]} for n in subnets
        }

        # floating ips
        ips = self._get_floating_ips(
            floating_ips=floatingips, network_map=network_map, tenant_map=tenant_map
        )
        ips.update(
            self._get_router_ips(
                routers=routers,
                ports=ports,
                tenant_map=tenant_map,
                network_map=network_map,
            )
        )
        for k, v in ips.items():
            neutron_public_ip_usage.labels(*k).set(v)

        # subnets
        for n in networks:
            size = 0
            for subnet in n["subnets"]:
                for pool in subnet_map[subnet]["pool"]:
                    if ":" in pool["start"]:
                        # Skip IPv6 address pools; they are big enough to
                        # drown the IPv4 numbers we might care about.
                        continue
                    size += IPRange(pool["start"], pool["end"]).size
            label_values = [self.config["cloud"], network_map[n["id"]]]
            neutron_net_size.labels(*label_values).set(size)


class Cinder(Collector):
    def collect(self, tenants, cinder, **kwargs):
        if not self.config.get("use_nova_volumes", True):
            return

        tenant_map = {t["id"]: t["name"] for t in tenants}
        for t in tenants:
            tid = t["id"]
            quota = cinder.quotas.get(tid, usage=True)._info

            if tid in tenant_map:
                tenant = tenant_map[tid]
            else:
                tenant = "orphaned"

            for tt in ["limit", "in_use", "reserved"]:
                cinder_quota_volume_disk_gigabytes.labels(
                    self.config["cloud"], tenant, tt
                ).inc(quota["gigabytes"][tt])
                cinder_quota_volume_disks.labels(self.config["cloud"], tenant, tt).inc(
                    quota["volumes"][tt]
                )


class Nova(Collector):
    def collect(self, tenants, nova, **kwargs):
        hypervisors = [x._info for x in nova.hypervisors.list()]
        services = [x._info for x in nova.services.list()]
        flavors = [x._info for x in nova.flavors.list(is_public=None)]
        aggregates = [x.to_dict() for x in nova.aggregates.list()]
        instances = []

        # Exclude instances in 'BUILD' state as they cannot be used as markers:
        #   https://github.com/CanonicalLtd/prometheus-openstack-exporter/issues/90
        valid_statuses = [
            "ACTIVE",
            "ERROR",
            "SHELVED_OFFLOADED",
            "SHUTOFF",
            "SUSPENDED",
            "VERIFY_RESIZE",
        ]
        for status in valid_statuses:
            marker = ""
            while True:
                search_opts = {
                    "all_tenants": "1",
                    "limit": "100",
                    "marker": marker,
                    "status": status,
                }
                new_instances = [
                    x._info for x in nova.servers.list(search_opts=search_opts)
                ]
                if new_instances:
                    marker = new_instances[-1]["id"]
                    instances.extend(new_instances)
                else:
                    break

        nova_quotas = {}
        for t in tenants:
            tid = t["id"]
            # old OS versions (e.g. Mitaka) will 404 if we request details
            try:
                nova_quotas[tid] = nova.quotas.get(tid, detail=True)._info
            except Exception:
                nova_quotas[tid] = nova.quotas.get(tid)._info

        tenant_map = {t["id"]: t["name"] for t in tenants}
        flavor_map = {
            f["id"]: {"ram": f["ram"], "disk": f["disk"], "vcpus": f["vcpus"]}
            for f in flavors
        }
        aggregate_map = {}
        services_map = {}
        for s in services:
            if s["binary"] == "nova-compute":
                services_map[s["host"]] = s["status"]
        for agg in aggregates:
            aggregate_map.update({i: agg["name"] for i in agg["hosts"]})

        self._gen_hypervisor_stats(
            hypervisors=hypervisors,
            aggregate_map=aggregate_map,
            services_map=services_map,
        )
        self._gen_instance_stats(
            tenant_map=tenant_map, instances=instances, flavor_map=flavor_map
        )
        self._gen_overcommit_stats()
        self._gen_quota_stats(nova_quotas=nova_quotas, tenant_map=tenant_map)

    def _get_schedulable_instances(self, host):
        free_vcpus = (
            host["vcpus"] * self.config["openstack_allocation_ratio_vcpu"]
            - host["vcpus_used"]
        )
        free_ram_mbs = (
            host["memory_mb"] * self.config["openstack_allocation_ratio_ram"]
            - host["memory_mb_used"]
        )
        free_disk_gbs = (
            host["local_gb"] * self.config["openstack_allocation_ratio_disk"]
            - host["local_gb_used"]
        )
        s = self.config["schedulable_instance_size"]
        if s["disk_gbs"] > 0:
            return min(
                int(free_vcpus / s["vcpu"]),
                int(free_ram_mbs / s["ram_mbs"]),
                int(free_disk_gbs / s["disk_gbs"]),
            )
        else:
            return min(int(free_vcpus / s["vcpu"]), int(free_ram_mbs / s["ram_mbs"]))

    def _get_schedulable_instances_capacity(self, host):
        capacity_vcpus = host["vcpus"] * self.config["openstack_allocation_ratio_vcpu"]
        capacity_ram_mbs = (
            host["memory_mb"] * self.config["openstack_allocation_ratio_ram"]
        )
        capacity_disk_gbs = (
            host["local_gb"] * self.config["openstack_allocation_ratio_disk"]
        )
        s = self.config["schedulable_instance_size"]
        if s["disk_gbs"] > 0:
            return min(
                int(capacity_vcpus / s["vcpu"]),
                int(capacity_ram_mbs / s["ram_mbs"]),
                int(capacity_disk_gbs / s["disk_gbs"]),
            )
        else:
            return min(
                int(capacity_vcpus / s["vcpu"]), int(capacity_ram_mbs / s["ram_mbs"])
            )

    def _gen_hypervisor_stats(self, hypervisors, aggregate_map, services_map):
        def squashnone(val, default=0):
            if val is None:
                return default
            return val

        for h in hypervisors:
            log.debug("Hypervisor: %s", h)
            host = h["service"]["host"]
            log.debug("host: %s", host)
            cpu_info = h["cpu_info"]
            log.debug("cpu_info: %s", cpu_info)
            arch = "Unknown"
            if not cpu_info:
                log.info("Could not get cpu info")
            elif type(cpu_info) != dict:
                cpu_info = json.loads(cpu_info)
                arch = cpu_info["arch"]
            label_values = [
                self.config["cloud"],
                host,
                aggregate_map.get(host, "unknown"),
                services_map[host],
                arch,
            ]
            # Disabled hypervisors return None below, convert to 0
            hypervisor_running_vms.labels(*label_values).set(
                squashnone(h["running_vms"])
            )
            hypervisor_vcpus_total.labels(*label_values).set(squashnone(h["vcpus"]))
            hypervisor_vcpus_used.labels(*label_values).set(squashnone(h["vcpus_used"]))
            hypervisor_memory_mbs_total.labels(*label_values).set(
                squashnone(h["memory_mb"])
            )
            hypervisor_memory_mbs_used.labels(*label_values).set(
                squashnone(h["memory_mb_used"])
            )
            hypervisor_disk_gbs_total.labels(*label_values).set(
                squashnone(h["local_gb"])
            )
            hypervisor_disk_gbs_used.labels(*label_values).set(
                squashnone(h["local_gb_used"])
            )

            if self.config.get("schedulable_instance_size", False):
                hypervisor_schedulable_instances.labels(*label_values).set(
                    self._get_schedulable_instances(h)
                )
                hypervisor_schedulable_instances_capacity.labels(*label_values).set(
                    self._get_schedulable_instances_capacity(h)
                )

    def _gen_instance_stats(self, tenant_map, instances, flavor_map):
        for i in instances:
            if i["tenant_id"] in tenant_map:
                tenant = tenant_map[i["tenant_id"]]
            else:
                tenant = "orphaned"
            nova_instances.labels(
                self.config["cloud"], i["name"], tenant, i["status"]
            ).inc()

            if i["flavor"]["id"] in flavor_map:
                flavor = flavor_map[i["flavor"]["id"]]
                nova_resources_ram_mbs.labels(self.config["cloud"], tenant).inc(
                    flavor["ram"]
                )
                nova_resources_vcpus.labels(self.config["cloud"], tenant).inc(
                    flavor["vcpus"]
                )
                nova_resources_disk_gbs.labels(self.config["cloud"], tenant).inc(
                    flavor["disk"]
                )

    def _gen_overcommit_stats(self):
        label_values = [self.config["cloud"], "vcpu"]
        openstack_allocation_ratio.labels(*label_values).set(
            self.config["openstack_allocation_ratio_vcpu"]
        )
        label_values = [self.config["cloud"], "ram"]
        openstack_allocation_ratio.labels(*label_values).set(
            self.config["openstack_allocation_ratio_ram"]
        )
        label_values = [self.config["cloud"], "disk"]
        openstack_allocation_ratio.labels(*label_values).set(
            self.config["openstack_allocation_ratio_disk"]
        )

    def _gen_quota_stats(self, nova_quotas, tenant_map):
        for t, q in nova_quotas.items():
            if t in tenant_map:
                tenant = tenant_map[t]
            else:
                tenant = "orphaned"

            # we get detailed quota information only on recent OS versions
            if isinstance(q["cores"], int):
                nova_quota_cores.labels(self.config["cloud"], tenant, "limit").set(
                    q["cores"]
                )
                nova_quota_floating_ips.labels(
                    self.config["cloud"], tenant, "limit"
                ).set(q["floating_ips"])
                nova_quota_instances.labels(self.config["cloud"], tenant, "limit").set(
                    q["instances"]
                )
                nova_quota_ram_mbs.labels(self.config["cloud"], tenant, "limit").set(
                    q["ram"]
                )
            else:
                for tt in ["limit", "in_use", "reserved"]:
                    nova_quota_cores.labels(self.config["cloud"], tenant, tt).inc(
                        q["cores"][tt]
                    )
                    nova_quota_floating_ips.labels(
                        self.config["cloud"], tenant, tt
                    ).inc(q["floating_ips"][tt])
                    nova_quota_instances.labels(self.config["cloud"], tenant, tt).inc(
                        q["instances"][tt]
                    )
                    nova_quota_ram_mbs.labels(self.config["cloud"], tenant, tt).inc(
                        q["ram"][tt]
                    )
