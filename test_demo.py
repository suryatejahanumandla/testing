import json
import logging
import pytest
import requests as http_requests
import re
import time
import random
from stompest.error import StompConnectionError
from stompest.config import StompConfig
from stompest.protocol import StompSpec
from stompest.sync import Stomp

logging.basicConfig(level=logging.DEBUG)
HEADERS = {'content-type': 'application/json', 'Authorization': 'Basic QURNSU46UEFTU1dPUkQ='}
is_disc_complete = False


# -------------------------------
# Fixtures
# -------------------------------

@pytest.fixture(scope="module", autouse=True)
def tb(request, testbed, get_logfile):
    testbed.mock = testbed.MOCK(logfile=get_logfile('pma_mock.txt'))
    return testbed


@pytest.fixture(scope="module")
def session():
    return http_requests.Session()


@pytest.fixture(scope="module", autouse=True)
def connect_stomp(request, tb):
    stomp_connection = connect_to_amq(tb, topic="firefly.devicelayer.events")

    def disconnect_stomp():
        try:
            amq_disconnect(stomp_connection)
        except StompConnectionError:
            logging.info("Stomp connection error")

    request.addfinalizer(disconnect_stomp)
    return stomp_connection


@pytest.fixture(scope="module")
def pma_info(tb):
    return PmaDpuInfo(tb)


def connect_to_amq(tb, queue=False, topic=False):
    # Format the connection url
    dl_ff_ip, dl_north_rest = tb.dl_northside_rest.split(":")
    dl_activemq_stomp_port = 61613
    url = "tcp://{}:{}".format(dl_ff_ip, dl_activemq_stomp_port)
    # Create stomp config
    config = StompConfig(url)
    stomp = Stomp(config)
    # Connect to activemq
    stomp.connect()
    if queue:
        stomp.subscribe(queue, {StompSpec.ID_HEADER: u'testbench'})
    elif topic:
        stomp.subscribe('/topic/' + str(topic), {StompSpec.ID_HEADER: u'testbench'})
    # return the stomp
    return stomp


def amq_disconnect(stomp):
    # To disconnect from activemq
    stomp.disconnect()


class pmaURIs:
    def __init__(self):
        self.announcement = "/pma-announcement"
        self.boot = "/pma-boot"


class PmaDpuInfo:
    def __init__(self, tb):
        # pma credentials
        self.pma_user = 'adtran'
        self.pma_pass = 'adtran'
        self.pma_uri = "/pmaserver/restconf/data/adtran-pma:pmas/pma"
        self.dpu_uri = "/pmaserver/restconf/data/adtran-device-units:device-units/device-unit"
        self.pma_ip = tb.pma_ip
        self.pma_url = "https://{}:{}{}".format(self.pma_ip, 8443, self.pma_uri)
        self.dpu_url = "https://{}:{}{}".format(self.pma_ip, 8443, self.dpu_uri)
        self.pma_northside_rest = "{}:{}".format(self.pma_ip, 8443)
        self.pma_list = []
        self.du_list = []
        self.update_pma_config(tb)
        self.create_pma_dpu(3)

    def create_pma_dpu(self, pma_range):
        logging.info("pma creation")
        # set what your server accepts
        headers = {'Content-Type': 'application/xml'}
        for i in range(pma_range):
            self.pma_list.append("pma-" + str(i))
            self.du_list.append("dev-pma-" + str(i))
            try:
                dpu_req = http_requests.post(self.dpu_url, data=self.create_dpu(i), verify=False, headers=headers,
                                             auth=(self.pma_user, self.pma_pass))
                assert dpu_req.status_code == 201
                pma_req = http_requests.post(self.pma_url, data=self.create_pma(i), verify=False, headers=headers,
                                             auth=(self.pma_user, self.pma_pass))
                assert pma_req.status_code == 201
            except:
                pass

    def update_pma_config(self, tb):
        url = "http://{}/restconf/data/pma-proxy-details:device-layer".format(tb.dl_northside_rest)
        payload = {
            "host": self.pma_ip,
            "username": self.pma_user,
            "password": self.pma_pass,
            "port": 8443,
            "sslEnabled": True,
            "pmaProxyEnabled": True
        }
        http_requests.post(url, headers=HEADERS, data=json.dumps(payload))

    def create_pma(self, pma_name):
        pma_xml_req = """<?xml version='1.0' encoding='utf-8'?>
                    <adtn-pma:pma xmlns:adtn-pma="http://www.adtran.com/ns/yang/adtran-pma">
                        <adtn-pma:name>pma-""" + str(pma_name) + """</adtn-pma:name>
                        <adtn-pma:device-units>
                            <adtn-pma:device-unit>dev-pma-""" + str(pma_name) + """</adtn-pma:device-unit>
                        </adtn-pma:device-units>
                        <adtn-pma:device>
                            <adtn-pma:model-name>dpu508g</adtn-pma:model-name>
                            <adtn-pma:enabled>true</adtn-pma:enabled>
                        </adtn-pma:device>
                    </adtn-pma:pma>"""
        return pma_xml_req

    def create_dpu(self, dpu_name):
        dpu_xml_req = """<?xml version='1.0' encoding='utf-8'?>
                    <adtn-dev-unit:device-unit xmlns:adtn-dev-unit="http://www.adtran.com/ns/yang/adtran-device-units">
                        <adtn-dev-unit:name>dev-pma-""" + str(dpu_name) + """</adtn-dev-unit:name>
                        <adtn-dev-unit:enabled>true</adtn-dev-unit:enabled>
                        <adtn-dev-unit:device-id>
                            <adtn-dev-unit:mac-address>""" + self.random_mac() + """</adtn-dev-unit:mac-address>
                            <adtn-dev-unit:model-name>dpu508g</adtn-dev-unit:model-name>
                        </adtn-dev-unit:device-id>
                    </adtn-dev-unit:device-unit>"""
        return dpu_xml_req

    def random_mac(self):
        mac = [0x00, 0x24, 0x81,
               random.randint(0x00, 0x7f),
               random.randint(0x00, 0xff),
               random.randint(0x00, 0xff)]
        new_mac = ':'.join(map(lambda x: "%02x" % x, mac))
        return new_mac


def proxy_url(tb, query, pma_id, device_agent_by_name=False, device_by_name=False):
    url = {"ip": tb.dl_northside_rest, "rest_interface_level": None, "query": query, "pma_id": pma_id}
    if device_agent_by_name:
        url["rest_interface_level"] = "device-agent-by-name:device-layer"
    elif device_by_name:
        url["rest_interface_level"] = "device-by-name:device-layer"
    else:
        url["rest_interface_level"] = ""
    url = "http://{}/restconf/data/{}/devices/device={}/{}".format(url["ip"], url["rest_interface_level"],
                                                                   url["pma_id"], url["query"])
    return url


def verify_proxy(pma_info, query, device_id, response, pma_enable=False, device_unit_enable=False,
                 device_agent_by_name=False,
                 device_by_name=False):
    url = None
    headers = {'Accept': 'application/json'}
    if device_agent_by_name:
        # https://<pmaa_ip>:<port>/pmaserver/restconf/data/adtran-pma:pmas-state/pma=<pma-id>
        url = "https://{}/pmaserver/restconf/data/{}".format(pma_info.pma_northside_rest, query)
    elif device_by_name:
        # https://<pmaa_ip>:<port>/dpudatastore/id=<pma-id>/restconf/data/ietf-interfaces:interfaces
        url = "https://{}/dpudatastore/id={}/restconf/data/{}".format(pma_info.pma_northside_rest, device_id, query)
    else:
        url = ""
        logging.info("restconf interface level not defined.")
    if pma_enable:
        proxy_resp = http_requests.get("{}/pma={}".format(url, device_id), verify=False, headers=headers,
                                       auth=(pma_info.pma_user, pma_info.pma_pass))
    elif device_unit_enable:
        proxy_resp = http_requests.get("{}/device-unit={}".format(url, device_id), verify=False, headers=headers,
                                       auth=(pma_info.pma_user, pma_info.pma_pass))
    else:
        logging.info("pma/device-unit not defined.")

    old_data = response
    comp_response = None
    if response:
        new_data = proxy_resp.json()
        comp_response = cmp(old_data, new_data)
    if comp_response == 0:
        return {"status_code": proxy_resp.status_code, "is_resp_matched": True}
    else:
        return {"status_code": proxy_resp.status_code, "is_resp_matched": False}


def get_notification_uri(stomp_connection):
    stomp = stomp_connection
    dis_time = 100
    is_disc_complete = False
    start_time = int(round(time.time() * 1000))
    uri = None
    while not is_disc_complete:
        frame = None
        current_time = int(round(time.time() * 1000))
        time_spent = (current_time - start_time) / 1000
        while stomp.canRead(1):
            try:
                frame = stomp.receiveFrame()
            except StompConnectionError:
                logging.info("Stomp connection error")
        if frame is not None:
            message = str(frame.body)
            search_msg = re.search(r"(/pma-.*t)", message)
            uri = search_msg.group()
            global is_disc_complete
            is_disc_complete = True
        elif time_spent > dis_time:
            global is_disc_complete
            is_disc_complete = True
    return uri


def pma_discovery_payload(pma_info):
    payload = {
        "host": pma_info.pma_ip,
        "uri": "/pmaserver/restconf/data",
        "username": pma_info.pma_user,
        "password": pma_info.pma_pass,
        "port": 8443,
        "sslEnabled": True,
        "eventStreamUri": "/eventstreams/xml/netconf/pmas/0"
    }
    return payload


# -------------------------------
# Tests
# -------------------------------
# Make sure we can send pma discovery request
def test_discover_pma_northbound_request(tb, connect_stomp, pma_info):
    # discovering pma
    url = "http://{}/restconf/operations/adtran-device-proxy:discover-pma".format(tb.dl_northside_rest)
    notify_resp = http_requests.post(url, headers=HEADERS, data=json.dumps(pma_discovery_payload(pma_info)))
    assert notify_resp.status_code == 200
    notification_uri = get_notification_uri(connect_stomp)
    pma_discovery_uri = pmaURIs()
    assert notification_uri == pma_discovery_uri.announcement


# verify with invalid credentials
def test_discover_pma_northbound_request_invalid(tb, pma_info):
    # discovering pma
    url = "http://{}/restconf/operations/adtran-device-proxy:discover-pma".format(tb.dl_northside_rest)
    payload = pma_discovery_payload(pma_info)
    # Invalid password
    payload["password"] = "ganges"
    notify_resp = http_requests.post(url, headers=HEADERS, data=json.dumps(payload))
    # assert notify_resp.status_code == 401
    assert notify_resp.status_code == 500
    # Invalid username
    payload["username"] = ""
    notify_resp = http_requests.post(url, headers=HEADERS, data=json.dumps(payload))
    # assert notify_resp.status_code == 401
    assert notify_resp.status_code == 500


# Make sure we can send pma rediscovery request
def test_rediscover_pma_northbound_request(tb, connect_stomp, pma_info):
    # rediscovering pma
    url = "http://{}/restconf/operations/adtran-device-proxy:discover-pma".format(tb.dl_northside_rest)
    notify_resp = http_requests.post(url, headers=HEADERS, data=json.dumps(pma_discovery_payload(pma_info)))
    assert notify_resp.status_code == 200
    notification_uri = get_notification_uri(connect_stomp)
    pma_discovery_uri = pmaURIs()
    assert notification_uri == pma_discovery_uri.boot


def test_proxy_req_for_pmas_state(tb, pma_info):
    query = "adtran-pma:pmas-state"
    pma_list = pma_info.pma_list
    for pma_id in pma_list:
        url = proxy_url(tb, query, pma_id, device_agent_by_name=True)
        resp = http_requests.get("{}/pma={}".format(url, pma_id), headers=HEADERS)
        assert resp.status_code == 200
        pma_proxy_resp = resp.json()
        proxy_resp = verify_proxy(pma_info, query, pma_id, pma_proxy_resp, pma_enable=True, device_agent_by_name=True)
        assert proxy_resp["status_code"] == resp.status_code
        assert proxy_resp["is_resp_matched"] == True


def test_proxy_req_for_pmas_state_invalid(tb, pma_info):
    query = "adtran-pma:pmas-state"
    pma_id = "PMA_15"
    url = proxy_url(tb, query, pma_id, device_agent_by_name=True)
    resp = http_requests.get("{}/pma={}".format(url, pma_id), headers=HEADERS)
    assert resp.status_code == 404
    proxy_resp = verify_proxy(pma_info, query, pma_id, None, pma_enable=True, device_agent_by_name=True)
    assert proxy_resp["status_code"] == resp.status_code


def test_proxy_pma_info(tb, pma_info):
    query = "adtran-pma:pmas"
    pma_list = pma_info.pma_list
    for pma_id in pma_list:
        url = proxy_url(tb, query, pma_id, device_agent_by_name=True)
        resp = http_requests.get("{}/pma={}".format(url, pma_id), headers=HEADERS)
        assert resp.status_code == 200
        pma_proxy_resp = resp.json()
        proxy_resp = verify_proxy(pma_info, query, pma_id, pma_proxy_resp, pma_enable=True, device_agent_by_name=True)
        assert proxy_resp["status_code"] == resp.status_code
        assert proxy_resp["is_resp_matched"] == True


def test_proxy_dpu_state(tb, pma_info):
    query = "adtran-device-units:device-units-state"
    device_list = pma_info.du_list
    for dev_id in device_list:
        url = proxy_url(tb, query, dev_id, device_agent_by_name=True)
        resp = http_requests.get("{}/device-unit={}".format(url, dev_id), headers=HEADERS)
        assert resp.status_code == 200
        pma_proxy_resp = resp.json()
        proxy_resp = verify_proxy(pma_info, query, dev_id, pma_proxy_resp, device_unit_enable=True,
                                  device_agent_by_name=True)
        assert proxy_resp["status_code"] == resp.status_code
        assert proxy_resp["is_resp_matched"] == True


def test_proxy_dpu_state_invalid(tb, pma_info):
    query = "adtran-device-units:device-units-state"
    dev_id = "dev_1234"
    url = proxy_url(tb, query, dev_id, device_agent_by_name=True)
    resp = http_requests.get("{}/device-unit={}".format(url, dev_id), headers=HEADERS)
    assert resp.status_code == 404
    proxy_resp = verify_proxy(pma_info, query, dev_id, None, device_unit_enable=True, device_agent_by_name=True)
    assert proxy_resp["status_code"] == resp.status_code


def test_proxy_interfaces(tb, pma_info):
    query = "ietf-interfaces:interfaces"
    pma_list = pma_info.pma_list
    for pma_id in pma_list:
        url = proxy_url(tb, query, pma_id, device_by_name=True)
        resp = http_requests.get("{}/pma={}".format(url, pma_id), headers=HEADERS)
        # assert resp.status_code == 200
        assert resp.status_code == 400
        pma_proxy_resp = resp.json()
        proxy_resp = verify_proxy(pma_info, query, pma_id, pma_proxy_resp, pma_enable=True, device_by_name=True)
        assert proxy_resp["status_code"] == resp.status_code
        assert proxy_resp["is_resp_matched"] == True
